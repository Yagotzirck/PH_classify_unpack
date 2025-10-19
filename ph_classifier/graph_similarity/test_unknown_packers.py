'''Test how the net classifies packers that weren't included
in the training set.
Ideally, they should all be classified as 'Unknown'.
'''
import sys
import os
from collections import Counter

from ph_classifier.packhero import classifier
from ph_classifier import paths


def test(
    toolmode: str,      # e.g. '--clustering'
    cg_extractor: str   # '--radare2' or '--ghidra'
):
    # Helper functions
    def get_unknown_packer_stats(
        toolmode: str,
        cg_extractor: str,
        packer_samples_path: str
    ) -> tuple[str, Counter]:

        packer_name = os.path.basename(
            os.path.normpath(packer_samples_path)
        )

        sample_classifications = classifier(
            toolmode,
            packer_samples_path,
            cg_extractor
        )

        return \
            packer_name, \
            Counter(
                sample_classification[1]
                for sample_classification in sample_classifications
            )
        

    # tuple of tuples (packer_name, labels_counters)
    unk_packers_stats = tuple(
        (
            get_unknown_packer_stats(
                toolmode, 
                cg_extractor,
                os.path.join(
                    paths.DATASET_UNKNOWN_PACKERS_PATH,
                    unknown_packer
                )
            )
            for unknown_packer in os.listdir(paths.DATASET_UNKNOWN_PACKERS_PATH)
        )
    )

    print('\n', 70 * '=', sep='')
    for packer_name, packer_stats in unk_packers_stats:
        print(f"Results for {packer_name}:")
        curr_packer_count = 0

        for classification, count in packer_stats.most_common():
            print(f"\t{classification:<30}: {count}")
            curr_packer_count += count
        
        
        # Samples for which the tool couldn't extract the graph don't count
        curr_packer_count -= packer_stats.get('Invalid graph', 0)

        unknown_count = packer_stats['Unknown']
        unknown_ratio = unknown_count / curr_packer_count
        print(
            f"\nUnknown samples: {unknown_count} / {curr_packer_count} "
            f"({unknown_ratio})"
        )

        print('\n', 70 * '=', sep='')



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