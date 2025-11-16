import os

class UnspecifiedCallGraphGeneratorError(ValueError):
    def __init__(self):
        super().__init__(
            "You must specify the Call Graph generator to proceed.\n"
            "Valid options are:\n"
                "\t--radare2\n"
                "\t--ghidra"
        )

def rel_to_abs_path(relative_path: str) -> str:
    """Converts a path relative to this .py file to an absolute path."""
    return str(
        os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                relative_path
            )
        )
    )

#####################################################################
# Dataset-related folders (samples and generated Call Graphs)
#####################################################################
DATASET_SAMPLES_PATH            = rel_to_abs_path("./dataset/samples/")
DATASET_UNKNOWN_PACKERS_PATH    = rel_to_abs_path("./dataset/unknown_packers")
GENERATED_GRAPHS_BASE_PATH      = rel_to_abs_path("./dataset/graphs/")

GENERATED_GRAPHS_RADARE2_PATH   = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'radare2/'
)
os.makedirs(GENERATED_GRAPHS_RADARE2_PATH, exist_ok=True)

GENERATED_GRAPHS_GHIDRA_PATH    = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'ghidra/'
)
os.makedirs(GENERATED_GRAPHS_GHIDRA_PATH, exist_ok=True)

# radare2's train and test split folders
GRAPHS_TRAIN_RADARE2_PATH       = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'radare2_train/'
)
os.makedirs(GRAPHS_TRAIN_RADARE2_PATH, exist_ok=True)


GRAPHS_TEST_RADARE2_PATH       = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'radare2_test/'
)
os.makedirs(GRAPHS_TEST_RADARE2_PATH, exist_ok=True)

# ghidra's train and test split folders
GRAPHS_TRAIN_GHIDRA_PATH       = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'ghidra_train/'
)
os.makedirs(GRAPHS_TRAIN_GHIDRA_PATH, exist_ok=True)


GRAPHS_TEST_GHIDRA_PATH       = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'ghidra_test/'
)
os.makedirs(GRAPHS_TEST_GHIDRA_PATH, exist_ok=True)

#####################################################################
# Graphviz-related folders
#####################################################################
GENERATED_GRAPHVIZ_RADARE2_PATH = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'radare2_graphviz/'
)
os.makedirs(GENERATED_GRAPHVIZ_RADARE2_PATH, exist_ok=True)

GENERATED_GRAPHVIZ_GHIDRA_PATH = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    'ghidra_graphviz/'
)
os.makedirs(GENERATED_GRAPHVIZ_GHIDRA_PATH, exist_ok=True)


#####################################################################
# Generated training files' base folders
#####################################################################
TRAINING_GEN_FILES_BASE_PATH = rel_to_abs_path('./training_gen_files')
os.makedirs(TRAINING_GEN_FILES_BASE_PATH, exist_ok=True)

TRAINING_GEN_FILES_RADARE2_PATH = os.path.join(
    TRAINING_GEN_FILES_BASE_PATH,
    'radare2/'
)
os.makedirs(TRAINING_GEN_FILES_RADARE2_PATH, exist_ok=True)

TRAINING_GEN_FILES_GHIDRA_PATH = os.path.join(
    TRAINING_GEN_FILES_BASE_PATH,
    'ghidra/'
)
os.makedirs(TRAINING_GEN_FILES_GHIDRA_PATH, exist_ok=True)

#####################################################################
# List of dataset classes' paths 
#####################################################################
CLASSES_LIST_RADARE2_PATH = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'classes_list_radare2.txt'
)

CLASSES_LIST_GHIDRA_PATH = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'classes_list_ghidra.txt'
)

#####################################################################
# Models' paths 
#####################################################################
MODEL_RADARE2_PATH  = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'trained_net_radare2.pt'
)

MODEL_GHIDRA_PATH  = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'trained_net_ghidra.pt'
)

#####################################################################
# Cosine similarity matrices' paths 
#####################################################################
SIMILMAT_RADARE2_PATH = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'cosine_similarity_matrix.pkl'
)

SIMILMAT_GHIDRA_PATH = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'cosine_similarity_matrix.pkl'
)

#####################################################################
# Dissimilarity matrices' folders 
#####################################################################
DISSMATS_RADARE2_PATH = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'dissmats/'
)
os.makedirs(DISSMATS_RADARE2_PATH, exist_ok=True)

DISSMATS_GHIDRA_PATH = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'dissmats/'
)
os.makedirs(DISSMATS_GHIDRA_PATH, exist_ok=True)


#####################################################################
# Fixed thresholds files' paths
#####################################################################
FIXED_THRESHOLDS_RADARE2_PATH = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'fixed_thresholds.pkl'
)

FIXED_THRESHOLDS_GHIDRA_PATH = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'fixed_thresholds.pkl'
)
#####################################################################
# Clustering-related files
#####################################################################
FIXED_THRESHOLDS_INTRACLUSTER_RADARE2_PATH   = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'fixed_thresholds_intracluster.pkl'
)

FIXED_THRESHOLDS_INTRACLUSTER_GHIDRA_PATH   = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'fixed_thresholds_intracluster.pkl'
)

CLUSTERING_RADARE2_PATH    = os.path.join(
    TRAINING_GEN_FILES_RADARE2_PATH,
    'clustering.pkl'
)

CLUSTERING_GHIDRA_PATH    = os.path.join(
    TRAINING_GEN_FILES_GHIDRA_PATH,
    'clustering.pkl'
)