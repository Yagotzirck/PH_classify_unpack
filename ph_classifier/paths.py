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
# Model-related folders 
#####################################################################
MODEL_BASE_PATH     = rel_to_abs_path('./model/')
os.makedirs(MODEL_BASE_PATH, exist_ok=True)

MODEL_RADARE2_PATH  = os.path.join(
    MODEL_BASE_PATH,
    'trained_net_radare2.pt'
)

MODEL_GHIDRA_PATH  = os.path.join(
    MODEL_BASE_PATH,
    'trained_net_ghidra.pt'
)