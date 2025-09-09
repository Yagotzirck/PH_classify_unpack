import sys
import os

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

from collections import Counter

from ph_classifier.packhero import classifier
from ph_classifier import paths

def paths_setup(cg_extractor: str) -> str:
    if cg_extractor == '--radare2':
        TEST_SET_PATH = paths.GRAPHS_TEST_RADARE2_PATH
    elif cg_extractor == '--ghidra':
        TEST_SET_PATH = paths.GRAPHS_TEST_GHIDRA_PATH
    else:
        raise paths.UnspecifiedCallGraphGeneratorError()
    
    return TEST_SET_PATH

def test(
    toolmode: str,      # e.g. '--clustering'
    cg_extractor: str   # '--radare2' or '--ghidra'
):
    # Helper functions
    def samples_grouped_by_packer(
        toolmode: str,
        cg_extractor: str,
        test_set_path: str
    ) -> tuple[dict[str, tuple[tuple[str, str]]], int]:

        sample_classifications = classifier(
            toolmode,
            test_set_path,
            cg_extractor
        )

        num_total_samples = len(sample_classifications)

        packers = {
            sample_classification[0].partition('_')[0]
            for sample_classification in sample_classifications
        }

        packers_samples = {}
        for packer in packers:
            packers_samples[packer] = tuple(
                sample_classification
                for sample_classification in sample_classifications
                if sample_classification[0].partition('_')[0] == packer
            )
        
        return packers_samples, num_total_samples
    
    def create_confusion_matrix( 
        packers_samples: dict[str, tuple[tuple[str, str]]]
    ) -> tuple[np.ndarray, tuple[str, ...]]: 

        packer_labels = (
            *packers_samples.keys(),
            'Unknown'
        )
        num_labels = len(packer_labels)

        # Preallocate the confusion matrix
        conf_mat = np.zeros(
            (num_labels, num_labels),
            dtype=int
        )

        label_to_idx = {
            packer_label: packer_idx
            for packer_idx, packer_label in enumerate(packer_labels)
        }
        
        # Remove 'Unknown' label from packer_labels
        for x, curr_row_label in enumerate(packer_labels[:-1]): 
            curr_packer_classifications = packers_samples[curr_row_label]

            classifications_count = Counter(
                classification[1]
                for classification in curr_packer_classifications
            )

            for classification, count in classifications_count.items():
                y = label_to_idx[classification]
                conf_mat[x,y] = count
        
        return conf_mat, packer_labels


    TEST_SET_PATH = paths_setup(cg_extractor)
    
    packers_samples, num_total_samples = samples_grouped_by_packer(
        toolmode,
        cg_extractor,
        TEST_SET_PATH
    )

    conf_mat, packer_labels = create_confusion_matrix(packers_samples)



    # Create a tuple of tuples
    # (packer_name, correct_classifications, total_samples)
    packers_stats = tuple(
        (
            packer_label,
            conf_mat[i, i],
            np.sum(conf_mat[i,:])
        )
        # Remove 'Unknown' label from packer_labels
        for i, packer_label in enumerate(packer_labels[:-1])
    )

    total_correct_classifications = 0

    print(80 * '=')
    print(f"{'Packer':<30} | {'Correct':<10} | {'Total samples':<15} | {'Accuracy':<10}")
    print(80 * '-')
    for stat in packers_stats:
        print(f"{stat[0]:<30} | {stat[1]:<10} | {stat[2]:<15} | {stat[1] / stat[2]:<10}")
        print(80 * '-')
        total_correct_classifications += stat[1]

    print(
        f"{'Total':<30} | "
        f"{total_correct_classifications:<10} | "
        f"{num_total_samples:<15} | "
        f"{total_correct_classifications / num_total_samples:<10}"
    )
    print(80 * '-')

    print("Showing confusion matrix")
    disp = ConfusionMatrixDisplay(
        confusion_matrix=conf_mat,
        display_labels=packer_labels
    )

    disp.plot()
    plt.xticks(rotation=90)
    plt.show()


def main():
    if len(sys.argv) != 3:
        curr_filename = os.path.basename(__file__)
        print(
            f"Usage: {curr_filename} <toolmode> <cg_extractor>\n"
            "where:\n"
            "\t<toolmode> = '--clustering' | '--mean' | '--majority'\n"
            "\t<cg_extractor> = '--radare2' | '--ghidra'",
            file=sys.stderr
        )
        return

    toolmode = sys.argv[1]
    cg_extractor = sys.argv[2]

    test(toolmode, cg_extractor)


if __name__ == '__main__':
    main()