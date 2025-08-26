#!/usr/bin/env python3
import glob
import os
import sys
import types

import ph_classifier.graph_extraction.radare2_extract_custom_gcg as r2_gcg
from ph_classifier.paths import *

PACKED_FILES = glob.iglob(f"{DATASET_SAMPLES_PATH}/*")


def paths_setup(cg_extractor: str) -> tuple[types.ModuleType, str, str, str]:
    if cg_extractor == '--radare2':
        gcg = r2_gcg
        cg_extractor = 'radare2'
        GENERATED_GRAPHS_PATH = GENERATED_GRAPHS_RADARE2_PATH
        GENERATED_GRAPHVIZ_PATH = GENERATED_GRAPHVIZ_RADARE2_PATH
    elif cg_extractor == '--ghidra':
        raise ValueError('This will be implemented later')
        #gcg = ghidra_gcg
        #cg_extractor = 'ghidra'
        #GENERATED_GRAPHS_PATH = GENERATED_GRAPHS_GHIDRA_PATH
        #GENERATED_GRAPHVIZ_PATH = GENERATED_GRAPHVIZ_GHIDRA_PATH
    else:
        raise UnspecifiedCallGraphGeneratorError()
    
    return gcg, cg_extractor, GENERATED_GRAPHS_PATH, GENERATED_GRAPHVIZ_PATH 


def dataset_generator(
    cg_extractor: str,
    gen_graphml: bool = True,
    gen_graphviz: bool = False,
    regen_graphs: bool = False
) -> None:

    gcg, \
    cg_extractor, \
    GENERATED_GRAPHS_PATH, \
    GENERATED_GRAPHVIZ_PATH = paths_setup(cg_extractor)

    discarded_list = []

    for curr_file in PACKED_FILES:
        curr_file_name = os.path.basename(curr_file)
        curr_file_name_no_ext, _ = os.path.splitext(curr_file_name)
        print(f"Generating Call Graph for {curr_file_name}...")

        if (
            not os.path.exists(
                os.path.join(GENERATED_GRAPHS_PATH, curr_file_name_no_ext + ".xml")
            ) or
            regen_graphs
        ):
            if gen_graphviz:
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
                
            if gen_graphml and G is not None:
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


def main():
    if '--radare2' in sys.argv:
        cg_extractor = '--radare2'
    elif '--ghidra' in sys.argv:
        cg_extractor = '--ghidra'
    else:
        raise UnspecifiedCallGraphGeneratorError()

    gen_graphml =   True if '--graphml' in sys.argv else False 
    gen_graphviz =  True if '--gvzplots' in sys.argv else False
    regen_graphs =  True if '--regen' in sys.argv else False

    dataset_generator(cg_extractor, gen_graphml, gen_graphviz, regen_graphs)


if __name__ == '__main__':
    main()