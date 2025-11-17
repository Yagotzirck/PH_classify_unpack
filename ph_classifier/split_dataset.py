from ph_classifier.paths import *

import sys
import glob
import collections
import random
import os

def delete_previous_splits(cg_extractor: str):
    '''Delete previously created splits (if any).
    Parameter:
    - cg_extractor: The tool used to extract the call graphs.
    The only two allowed values are '--radare2' and '--ghidra'.
    '''
    if cg_extractor == '--radare2':
        reset_folders = (GRAPHS_TRAIN_RADARE2_PATH, GRAPHS_TEST_RADARE2_PATH)
    elif cg_extractor == '--ghidra':
        reset_folders = (GRAPHS_TRAIN_GHIDRA_PATH, GRAPHS_TEST_GHIDRA_PATH)
    else:
        raise UnspecifiedCallGraphGeneratorError()

    for folder in reset_folders: 
        for old_train_sample in glob.iglob(f'{folder}/*.xml'):
            os.remove(
                os.path.join(folder, old_train_sample)
            )


def split_dataset(cg_extractor: str, train_perc: float):
    """Splits the specified dataset into training and test sets.
    Parameters:
    - cg_extractor: The tool used to extract the call graphs.
    The only two allowed values are '--radare2' and '--ghidra';

    - train_perc (float): A value between 0 and 1, representing the
    proportion of the dataset to be used for training.
    For example, a value of 0.8 indicates that 80% of the data
    will be allocated to the training set.

    The test set proportion value will be simply given by
    (1 - train_perc).

    It also saves the list of packers (classes) present in the dataset.
    """

    if cg_extractor == '--radare2':
        graphs_path =       GENERATED_GRAPHS_RADARE2_PATH
        train_path  =       GRAPHS_TRAIN_RADARE2_PATH
        test_path   =       GRAPHS_TEST_RADARE2_PATH
        classes_list_path   = CLASSES_LIST_RADARE2_PATH
    elif cg_extractor == '--ghidra':
        graphs_path =       GENERATED_GRAPHS_GHIDRA_PATH
        train_path =        GRAPHS_TRAIN_GHIDRA_PATH
        test_path =         GRAPHS_TEST_GHIDRA_PATH
        classes_list_path = CLASSES_LIST_GHIDRA_PATH
    else:
        raise UnspecifiedCallGraphGeneratorError()

    # Make sure the order is always the same for reproducible results
    samples_list = sorted(glob.iglob(f'{graphs_path}/*.xml'))

    packers_samples = collections.defaultdict(list) 

    for sample in samples_list:
        packer = os.path.basename(sample).partition('_')[0]
        packers_samples[packer].append(sample)
    
    # Save the list of dataset classes
    with open(classes_list_path, 'w') as out_fp:
        packers = '\n'.join(
            packer_name
            for packer_name in packers_samples.keys()
        )
        out_fp.write(packers)

    # Split the dataset in training and test sets
    random.seed(42)

    for curr_packer_samples in packers_samples.values():
        random.shuffle(curr_packer_samples)

        num_packer_samples = len(curr_packer_samples)
        num_train_samples = int(num_packer_samples * train_perc)

        # The first num_train_samples will be linked in the train directory
        for train_file in curr_packer_samples[:num_train_samples]:
            train_filename = os.path.basename(train_file)
            dest_link = os.path.join(train_path, train_filename)
            os.link(train_file, dest_link)
        
        # The remaining samples will be linked in the test directory
        for test_file in curr_packer_samples[num_train_samples:]:
            test_filename = os.path.basename(test_file)
            dest_link = os.path.join(test_path, test_filename)
            os.link(test_file, dest_link)

def main():
    if len(sys.argv) != 3:
        curr_filename = os.path.basename(__file__)
        print(
            f"Usage: python {curr_filename} <cg_extractor> <train_perc>\n"
            "where:\n"
            "\t<cg_extractor> == '--radare2' or '--ghidra';\n"
            "\t0 <= train_perc <= 1",
            file = sys.stderr
        )
        return

    cg_extractor = sys.argv[1]
    train_perc = float(sys.argv[2])

    if not ( 0 <= train_perc <= 1):
        raise ValueError("train_perc must be inside the range [0,1]")

    delete_previous_splits(cg_extractor)
    split_dataset(cg_extractor, train_perc)
    

if __name__ == '__main__':
    main()