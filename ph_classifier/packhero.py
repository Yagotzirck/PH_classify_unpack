import sys
import torch
import tempfile
import time
import math
from os import listdir
from collections import defaultdict
from progress.bar import IncrementalBar
import types

from .graph_extraction import radare2_extract_custom_gcg as r2_gcg
from .graph_similarity.configure import *
from .tool_dependencies.tool_dataset import *
from .tool_dependencies.utils import *
from .graph_similarity.evaluation import *
from . import paths


THRESHOLD_MEDOIDS_SIMILARITY = 0.8 # default THRESHOLD for cosine similarity between input and clusterings medoids
THRESHOLD_CLUSTERING_SIMILARITY = 0.95 # default THRESHOLD for cosine similarity between input and selected clusterings
THRESHOLD_CLUSTERING_MATCH = 0.5 # default THRESHOLD for proportion of matches in selected clusterings
THRESHOLD_MAJORITY_SIMILARITY = 0.6 # default THRESHOLD for cosine similarity in majority mode
THRESHOLD_MAJORITY_MATCH = 0.1 # default THRESHOLD proportion of matches in majority mode
THRESHOLD_MEAN = 0.6 # default THRESHOLD for cosine similarity in mean mode

def paths_setup(cg_extractor: str) -> tuple[str, str, str, types.ModuleType]:
    if cg_extractor == '--radare2':
        MODEL_PATH = paths.MODEL_RADARE2_PATH
        DB_PATH = paths.GRAPHS_TRAIN_RADARE2_PATH
        CLUSTERING_PATH = paths.CLUSTERING_RADARE2_PATH
        gcg = r2_gcg
    elif cg_extractor == '--ghidra':
        raise ValueError('This will be implemented later')
        MODEL_PATH = paths.MODEL_GHIDRA_PATH
        DB_PATH = paths.GRAPHS_TRAIN_GHIDRA_PATH
        CLUSTERING_PATH = paths.CLUSTERING_GHIDRA_PATH
        gcg = ghidra_gcg
    else:
        raise paths.UnspecifiedCallGraphGeneratorError()
    
    return MODEL_PATH, DB_PATH, CLUSTERING_PATH, gcg

def file_analysis(
    filepath: str,
    toolmode: str,
    discard: bool,
    threshold_majority_similarity: float,
    threshold_majority_match: float,
    threshold_mean: float,
    db_path: str,
    clustering_path: str,
    normalization_mean: float,
    normalization_std: float,
    config: dict,
    device,
    model,
    gcg: types.ModuleType
):

    print("filename: " + filepath.split("/")[-1])

    # Tool runned in standard mode (PE file as input), so it has to extract the graph from the PE file before the evaluation
    if not filepath.endswith(".xml"):
        
        # extract call graph from PE file
        print("Extracting call graph from PE file...")
        if not discard:
            G = gcg.extract_gcg(filepath, discard=False)
        else:
            G = gcg.extract_gcg(filepath)

        # Due to the matching method, the assumption we made is that the graph extracted from the PE file has less than 200 nodes
        if G == None:
            print("Error: the graph extracted has more than 200 nodes!")
            exit(1)

        tmp_file = tempfile.NamedTemporaryFile(suffix=".xml")
        graph_path = tmp_file.name
        gcg.save_graph_networkx(G, graph_path)
        print("Graph extracted!")

    # Mode tool with xml files (graphs already extracted)
    else:
    
        graph_path = filepath

    # EVALUATION
    model.eval()
    start_time = time.time()

    print("\nEvaluating...")

    with torch.no_grad():
        similarities = defaultdict(lambda: torch.tensor([]))

        # Clustering mode
        if toolmode == "--clustering":
            
            with open(clustering_path, 'rb') as f:
                clusters_info = pickle.load(f)

            print("Selecting the closer cluster(s)...")

            medoids = [clusters_info['filenames'][index] for index in clusters_info['medoids']]
            dataset_medoids = PackedGraphSimilarityPairs(db_path,graph_path,normalization_mean,normalization_std, included_files=medoids)

            similarities = np.array([])

            # Batch size must be 1 to evaluate the closer cluster
            for batch_graphs, batch_packers, _ in dataset_medoids.pairs(dataset_medoids.get_db_size()):
                    node_features, edge_features, from_idx, to_idx, graph_idx = get_graph(batch_graphs)
                    eval_pairs = model(node_features.to(device), edge_features.to(device), from_idx.to(device),
                                        to_idx.to(device),
                                        graph_idx.to(device), dataset_medoids.get_db_size() * 2)
                    
                    x, y = reshape_and_split_tensor(eval_pairs, 2)
                    similarity = compute_similarity(config, x, y)

                    for i in range(dataset_medoids.get_db_size()):
                        similarities = np.append(similarities, similarity[i].item())

            # Get the closer cluster
            closer_clusters_medoids = [medoids[i] for i in range(len(similarities)) if similarities[i] > THRESHOLD_MEDOIDS_SIMILARITY]
            if closer_clusters_medoids == []:
                return None
            closer_clusters_indexes = [clusters_info['cluster_labels'][clusters_info['filenames'].index(closer_cluster_medoid)] for closer_cluster_medoid in closer_clusters_medoids]

            print("Closer clusters' medoid: ", closer_clusters_medoids)

            filenames = [clusters_info['filenames'][index] for index in range(len(clusters_info['filenames'])) if clusters_info['cluster_labels'][index] in closer_clusters_indexes]
            dataset = PackedGraphSimilarityPairs(db_path,graph_path,normalization_mean,normalization_std, included_files=filenames)

            bar = IncrementalBar('Comparison', max = dataset.get_db_size())

            similarities = defaultdict(lambda: np.array([]))

            # Evaluate the model on the test dataset
            files_analyzed = 0 # To discard last duplicates in the pairs due to the batch size

            batch_size = config['evaluation']['batch_size']

            if dataset.get_db_size() < batch_size:
                batch_size = dataset.get_db_size()

            for batch_graphs, batch_packers, _ in dataset.pairs(batch_size):
                node_features, edge_features, from_idx, to_idx, graph_idx = get_graph(batch_graphs)
                eval_pairs = model(node_features.to(device), edge_features.to(device), from_idx.to(device),
                                    to_idx.to(device),
                                    graph_idx.to(device), batch_size * 2)
                
                x, y = reshape_and_split_tensor(eval_pairs, 2)
                similarity = compute_similarity(config, x, y)

                if files_analyzed + batch_size > dataset.get_db_size():
                        
                    for i in range(dataset.get_db_size() - files_analyzed):
                            similarities[batch_packers[i]] = np.append(similarities[batch_packers[i]], similarity[i].item())
                    bar.next(dataset.get_db_size() - files_analyzed)

                else:

                    for i in range(batch_size):
                        similarities[batch_packers[i]] = np.append(similarities[batch_packers[i]], similarity[i].item())

                    bar.next(batch_size)

                    files_analyzed += batch_size

            if similarities == None:
                identified_packer = "Unknown"
            else:
                # Compute proportion of matches for each packer and choose max
                scores = defaultdict(lambda: 0)
                num_packer = {packer: len(similarities[packer]) for packer in similarities}
                max_num_packer = max(num_packer.values())
                for packer in similarities:
                    for similarity in similarities[packer]:
                        if similarity > THRESHOLD_CLUSTERING_SIMILARITY:
                            scores[packer] += 1

                    scores[packer] = scores[packer]/max_num_packer

                print()
                print("Scores: ", scores.items())

                max_score = max(scores.values())

                if max_score > THRESHOLD_CLUSTERING_MATCH:
                    identified_packer = max(scores, key=scores.get) + " (percentage of weighted matches in the selected clusters for the identified packer: " + str(round(max_score*100, 2)) + "%)"
                else:
                    identified_packer = "Unknown"
        # Mean or Majority mode
        else:

            # Test dataset to evaluate the model
            dataset = PackedGraphSimilarityPairs(db_path,graph_path,normalization_mean,normalization_std)

            bar = IncrementalBar('Comparison', max = dataset.get_db_size())

            start_time = time.time()

            # Evaluate the model on the test dataset
            files_analyzed = 0 # To discard last duplicates in the pairs due to the batch size

            batch_size = config['evaluation']['batch_size']

            if dataset.get_db_size() < batch_size:
                batch_size = dataset.get_db_size()

            for batch_graphs, batch_packers, _ in dataset.pairs(batch_size):
                node_features, edge_features, from_idx, to_idx, graph_idx = get_graph(batch_graphs)
                eval_pairs = model(node_features.to(device), edge_features.to(device), from_idx.to(device),
                                    to_idx.to(device),
                                    graph_idx.to(device), config['evaluation']['batch_size'] * 2)
                
                x, y = reshape_and_split_tensor(eval_pairs, 2)
                similarity = compute_similarity(config, x, y)

                if files_analyzed + batch_size > dataset.get_db_size():

                    for i in range(dataset.get_db_size() - files_analyzed):
                            similarities[batch_packers[i]] = torch.cat((similarities[batch_packers[i]], torch.tensor([similarity[i].item()])))
                    bar.next(dataset.get_db_size() - files_analyzed)

                else:

                    for i in range(batch_size):
                            similarities[batch_packers[i]] = torch.cat((similarities[batch_packers[i]], torch.tensor([similarity[i].item()])))
                    bar.next(batch_size)

                    files_analyzed += batch_size

            # Mean mode
            if toolmode == "--mean":
                # Compute mean similarity for each packer and choose max using a treeshold of cosine similarity
                for packer in similarities:
                    similarities[packer] = torch.mean(similarities[packer]).item()

                max_similarity = max(similarities.values())
                if max_similarity > threshold_mean:
                    identified_packer = max(similarities, key=similarities.get) + " (mean similarity: " + str(round((max_similarity)*100, 2)) + "%)"
                else:
                    identified_packer = "Unknown"
            
            # Majority mode
            else:
                # Compute proportion of matches for each packer and choose max if it is greater than threshold_matches (the graph has matched with at least threshold_matches*100% of the packer's graphs)
                scores = defaultdict(lambda: 0)
                for packer in similarities:
                    for similarity in similarities[packer]:
                        if similarity > threshold_majority_similarity:
                            scores[packer] += 1
                    scores[packer] = scores[packer]/len(similarities[packer])

                max_score = max(scores.values())
                if max_score > threshold_majority_match:
                    identified_packer = max(scores, key=scores.get) + " (percentage of matches with the identified packer: " + str(round(max_score*100, 2)) + "%)"
                else:
                    identified_packer = "Unknown"
                
    bar.finish()

    print()
    print("Matching time elapsed: ", time.time() - start_time)
    print("Identified Packer: ", identified_packer)

    if not filepath.endswith(".xml"):

        # close tmp file (only for PE mode)
        tmp_file.close()


def main():
    # Set GPU
    use_cuda = torch.cuda.is_available()
    use_cuda = False
    device = torch.device('cuda' if use_cuda else 'cpu')

    # import configuration
    config = get_default_config()

    if sys.argv[-1] in ('--radare2', '--ghidra'):
        cg_extractor = sys.argv[-1]
    else:
        raise paths.UnspecifiedCallGraphGeneratorError()

    MODEL_PATH, DB_PATH, CLUSTERING_PATH, gcg = paths_setup(cg_extractor)


    db_dataset = TrainingPackedGraphSimilarityDataset(DB_PATH,validation_size=config['data']['dataset_params']['validation_size'])
    # Extract normalization metrics from db
    normalization_mean, normalization_std, features_order = db_dataset.get_node_statistics()
    # Retrieve node and edge feature dimension
    node_feature_dim, edge_feature_dim = db_dataset.get_features_dim()

    # Build model from saved weights
    model, optimizer = build_model(config, node_feature_dim, edge_feature_dim)
    model.to(device)
    model.load_state_dict(torch.load(MODEL_PATH))

    # Extract info from the argvs
    toolmode = sys.argv[1]

    if len(sys.argv) > 3 and sys.argv[3] == "--nodiscard":
        discard = False
    else:
        discard = True

    print("identification mode: " + toolmode[2:] + "\n")

    # Directory mode
    if (sys.argv[2].endswith("/")):

        print("Directory mode\n")

        filenames = listdir(sys.argv[2])
        filenames.sort()
        
        for filename in filenames:

            filepath = sys.argv[2] + filename
            print("\n--------------------------------\n")
            file_analysis(
                filepath,
                toolmode,
                discard,
                THRESHOLD_MAJORITY_SIMILARITY,
                THRESHOLD_MAJORITY_MATCH,
                THRESHOLD_MEAN,
                DB_PATH,
                CLUSTERING_PATH,
                normalization_mean,
                normalization_std,
                config,
                device,
                model,
                gcg
            )

    # File mode
    else:

        print("File mode\n")

        filepath = sys.argv[2]

        file_analysis(
            filepath,
            toolmode,
            discard,
            THRESHOLD_MAJORITY_SIMILARITY,
            THRESHOLD_MAJORITY_MATCH,
            THRESHOLD_MEAN,
            DB_PATH,
            CLUSTERING_PATH,
            normalization_mean,
            normalization_std,
            config,
            device,
            model,
            gcg
        )

if __name__ == '__main__':
    main()