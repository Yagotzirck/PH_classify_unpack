import sys
import os

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
    

    TEST_SET_PATH = paths_setup(cg_extractor)
    
    packers_samples, num_total_samples = samples_grouped_by_packer(
        toolmode,
        cg_extractor,
        TEST_SET_PATH
    )

    # Create a tuple of tuples (packer_name, correct_classifications, total_samples)
    packers_stats = tuple(
        (
            packer_name,
            sum(
                1
                for sample in samples
                if sample[0].partition('_')[0] == sample[1]
            ),
            len(samples)
        )
        for packer_name, samples in packers_samples.items()
    )

    total_correct_classifications = 0
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