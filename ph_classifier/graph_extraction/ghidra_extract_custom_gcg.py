#!/usr/bin/env python3

from graphviz import Source
import tempfile

import networkx as nx
import matplotlib.pyplot as plt

import os
import sys
from collections import deque, defaultdict

from .ghidra_extract_functions import ghidra_extract_functions

MAX_NUM_NODES = 500

def save_graph_networkx(G, save_filepath):
    file_path = os.path.dirname(save_filepath)
    filename_no_ext = os.path.splitext(
        os.path.basename(save_filepath)
    )[0]

    save_filepath = os.path.join(
        file_path,
        f'{filename_no_ext}.xml'
    )
    nx.write_graphml(G, save_filepath)

def save_graph_pdf(dot_graph, save_filepath):
    s = Source(dot_graph)
    s.render(save_filepath, format='pdf', cleanup=True)

def plot_graph_pdf(dot_graph):
    
    s = Source(dot_graph)
    s.view(tempfile.mktemp('.gv'))

def plot_graph_plt(G):

    options = {
        'node_size': 0,
        'width': 1,
        'arrowsize': 20,
        'font_size': 12,
        'bbox': dict(facecolor = "skyblue")
    }
    plt.figure(1,figsize=(60,15))
    pos = nx.nx_agraph.graphviz_layout(G, prog = "dot", args='-Grankdir=LR')
    nx.draw(G, pos=pos, with_labels=True, **options)
    plt.show()


# This function extracts the global callgraph manually
# by iterating on all functions detected by Ghidra
def extract_gcg(filepath, discard = True):

    try:
        funcs_features, called_funcs = ghidra_extract_functions(filepath)
    except Exception as e:
        print('\t', e, sep='', file=sys.stderr)
        return None


    # Initialize the graph
    G = nx.DiGraph()

    # Add in the graph all entry points as nodes
    G.add_nodes_from(
        (func_name, func_features)
        for func_name, func_features in funcs_features.items()
        if func_name.startswith('entry')
    )

    # Make sure that the first analyzed function is the entry point,
    # or at the very least the function with the lowest address
    extracted_funcs_names = sorted(
        func_name
        for func_name in funcs_features.keys()
        if not '::' in func_name
    )

    # Append the imported functions at the end
    extracted_funcs_names.extend(
        func_name
        for func_name in funcs_features.keys()
        if '::' in func_name
    )

    try:
        entry_idx = extracted_funcs_names.index('entry')
    except ValueError:
        # Ghidra might still detect some functions (e.g. NSPack),
        # so don't abort just yet
        print("\tEntry point not found; proceeding anyway...")
    else:
        # Swap the entry point with the function in the list's 1st element
        extracted_funcs_names[0], extracted_funcs_names[entry_idx] = (
            extracted_funcs_names[entry_idx],
            extracted_funcs_names[0]
        )

    for func_name in extracted_funcs_names:

        # if more than MAX_NUM_NODES nodes return None (discard the sample)
        if G.number_of_nodes() > MAX_NUM_NODES and discard:
            print(
                f"\tThe graph has {G.number_of_nodes()} nodes\n"
                f"\t(max threshold: {MAX_NUM_NODES})",
                file=sys.stderr
            )
            return None

        # Stop if number of edges is greater than 0 (there is one connected component)
        if G.number_of_edges() > 0:
            break

        to_explore = deque()
        to_explore.append(func_name)
        explored = defaultdict(lambda: False)

        G.add_node(func_name, **funcs_features[func_name])
        
        while len(to_explore) > 0:

            # if more than MAX_NUM_NODES nodes return None (discard the sample)
            if G.number_of_nodes() > MAX_NUM_NODES and discard:
                print(
                    f"\tThe graph has {G.number_of_nodes()} nodes\n"
                    f"\t(max threshold: {MAX_NUM_NODES})",
                    file=sys.stderr
                )
                return None
            
            # Pop from left of the dequeue a function and mark the function as explored
            func_name = to_explore.popleft()

            if explored[func_name]:
                continue

            explored[func_name] = True

            # Forward edges.
            # NOTE: the external (imported) functions aren't included in
            # the dict 'called_funcs', so we'll just return an empty set
            # for those

            for called_func_name in called_funcs.get(func_name, set()):
                if called_func_name not in G.nodes():
                    G.add_node(
                        called_func_name,
                        **funcs_features[called_func_name]
                    )
                if func_name not in G.nodes():
                    G.add_node(
                        func_name,
                        **funcs_features[func_name]
                    )

                # Add edge between func_name and called_func_name
                if not G.has_edge(func_name, called_func_name):
                    G.add_edge(func_name, called_func_name)
                
                if not explored[called_func_name]:
                    to_explore.append(called_func_name)

    # Drop all isolates except for entry and symbols
    to_drop = list(nx.isolates(G))
    to_drop = [node for node in to_drop if "DLL" not in node.upper() and not node.startswith("entry")]
    G.remove_nodes_from(to_drop)

    if G.number_of_nodes() == 0:
        print(
            "No functions have been found in the sample",
            file=sys.stderr
        )
        return None

    return G

# This function extracts the global callgraph (with plots) manually by iterating on all functions radare2 detects ("aflj" command)
def extract_gcg_with_plot(filepath):

    G = extract_gcg(filepath)

    dot_format = """
    digraph code {
    rankdir=LR;
    outputorder=edgesfirst;
    graph [bgcolor=white fontname="Courier" splines="curved"];
    node [penwidth=4 fillcolor=white style=filled fontname="Courier Bold" fontsize=14 shape=box];
    edge [arrowhead="normal" style=bold weight=2];"""

    # if sample has been discarded return None
    if G is None:
        return None, dot_format
    
    dot_graph = str(nx.nx_agraph.to_agraph(G)).replace('digraph "" {', dot_format)

    return G, dot_graph