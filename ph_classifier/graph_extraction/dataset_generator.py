#!/usr/bin/env python3

class UnspecifiedCallGraphGeneratorError(ValueError):
    def __init__(self):
        super().__init__(
            "You must specify the Call Graph generator to proceed.\n"
            "Valid options are:\n"
                "\t--radare2\n"
                "\t--ghidra"
        )


import glob
import os
import sys
import radare2_extract_custom_gcg as r2_gcg


DATASET_SAMPLES_PATH = "../dataset/samples"
GENERATED_GRAPHS_BASE_PATH = "../dataset/graphs"
PACKED_FILES = glob.iglob(f"{DATASET_SAMPLES_PATH}/*")


if '--radare2' in sys.argv:
    gcg = r2_gcg
    cg_extractor = 'radare2'
elif '--ghidra' in sys.argv:
    raise ValueError('This will be implemented later')
    #cg_extractor = 'ghidra'
else:
    raise UnspecifiedCallGraphGeneratorError()

GENERATED_GRAPHS_PATH = os.path.join(GENERATED_GRAPHS_BASE_PATH, cg_extractor)
os.makedirs(GENERATED_GRAPHS_PATH, exist_ok=True)

GENERATED_GRAPHVIZ_PATH = os.path.join(
    GENERATED_GRAPHS_BASE_PATH, f'{cg_extractor}_graphviz'
)
os.makedirs(GENERATED_GRAPHVIZ_PATH, exist_ok=True)

discarded_list = []

for curr_file in PACKED_FILES:
    curr_file_name = os.path.basename(curr_file)
    curr_file_name_no_ext, _ = os.path.splitext(curr_file_name)
    print(f"Generating Call Graph for {curr_file_name}...")

    if (
        not os.path.exists(
            os.path.join(GENERATED_GRAPHS_PATH, curr_file_name_no_ext + ".xml")
        ) or
        "--regenerate" in sys.argv
    ):
        if "--gvzplots" in sys.argv:

            G, dot_graph = gcg.extract_gcg_with_plot(curr_file)
            if G is None:
                discarded_list.append(curr_file_name)
            else:
                gcg.save_graph_pdf(
                    dot_graph,
                    os.path.join(GENERATED_GRAPHVIZ_PATH, curr_file_name_no_ext)
                )

        else:
            G = gcg.extract_gcg(curr_file)
            if G is None:
                discarded_list.append(curr_file_name)
            

        if "--graphml" in sys.argv and G is not None:
            gcg.save_graph_networkx(
                G,
                os.path.join(GENERATED_GRAPHS_PATH, curr_file_name_no_ext)
            )

print("\nDiscarded files: ", discarded_list)


# Save the list of discarded samples
out_discarded_list_filename = os.path.join(
    GENERATED_GRAPHS_BASE_PATH,
    f'discarded_samples_{cg_extractor}.txt' 
)

with open(out_discarded_list_filename, 'w') as out_fp:
        out_fp.writelines(
            f'{discarded_file}\n' for discarded_file in discarded_list
        )