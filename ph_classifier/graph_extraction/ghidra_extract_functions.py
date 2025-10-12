import pyghidra
pyghidra.start() # Otherwise we can't import ghidra modules
from ghidra.program.model.block import BasicBlockModel  # type: ignore
from ghidra.util.task import TaskMonitor                # type: ignore
from ghidra.program.model.symbol import SymbolType      # type: ignore
from ghidra.program.model.listing import Program        # type: ignore
from ghidra.app.util.opinion import LoadException       # type: ignore

import tempfile
import hashlib
from collections import defaultdict
import typing

if typing.TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI       # type: ignore
    from ghidra.program.model.listing import Function       # type: ignore
    from ghidra.program.model.listing import Instruction    # type: ignore


def ghidra_extract_functions(filepath: str) -> \
    tuple[dict[str, dict[str, int]], dict[str, set[str]]]:
    """Helper function for extract_gcg() that leverages Ghidra to
    extract functions from the exe given in the "filepath" arg, as well as
    extracting the required features and callrefs from each function.
    """

    ################### Nested helper functions ################### 
    def init_funcs_features_dict(
        binary_functions_names:     typing.Iterable[str],
        imported_functions_names:   typing.Iterable[str]
    ) -> dict[str, dict[str, int]]:

        def hash_2bytesChunks_iter(
            imported_curr_func_name: str,
            num_fields: int
        ) -> typing.Iterator[int]:

            hash = hashlib.sha224(imported_curr_func_name.encode()).hexdigest()
            if num_fields * 4 > len(hash): # 2 bytes = 4 hex digits
                raise ValueError(
                    "The requested number of fields can't be "
                    "filled by the hash's length"
                )
            
            for i in range(0, num_fields * 4, 4):   # 2 bytes = 4 hex digits
                yield int(hash[i: i+4], 16)


        feature_names = (
            'size',
            'num_basic_blocks',
            'num_instrs',
            'num_edges',
            'indegree',
            'outdegree',
            'num_local_vars',
            'num_params'
        )

        # Set all fields for binary functions to 0
        # (they will be initialized later)
        bin_funcs_dict = {
            name: {
                feature_name: 0
                for feature_name in feature_names
            }
            for name in binary_functions_names
        }

        # Initialize all fields for imported functions
        # by using the function name's sha256
        # (2-byte chunks for each field)
        imported_funcs_dict = {
            name: {
                feature_name: hash_chunk
                for feature_name, hash_chunk in zip(
                    feature_names,
                    hash_2bytesChunks_iter(name, len(feature_names))
                )
            }
            for name in imported_functions_names
        } 

        # Return the two merged dicts
        bin_funcs_dict.update(imported_funcs_dict)
        return bin_funcs_dict


    def names_to_functions(
        func_names:tuple[str, ...],
        flat_api:"FlatProgramAPI",
        prg:"Program"
    ) -> typing.Iterable["Function"]:
        return (
            flat_api.getFunctionAt(symbol.getAddress())
            for symbol in prg.getSymbolTable().getAllSymbols(True)
            if(
                symbol.getSymbolType() == SymbolType.FUNCTION and
                not symbol.isExternal() and
                symbol.getName(True) in func_names
            )
        )


    ################### End of nested helper functions ################### 


    with tempfile.TemporaryDirectory() as tmp_project_dir:
        with pyghidra.open_program(
            binary_path=filepath,
            project_location=tmp_project_dir,
            analyze=False
        ) as flat_api:

            flat_api = typing.cast("FlatProgramAPI", flat_api)
            prg = flat_api.getCurrentProgram()


            # Disable decompiler-related stuff, since:
            # 1) It's EXTREMELY time-consuming
            # 2) We don't really need it
            analysis_opts = prg.getOptions(Program.ANALYSIS_PROPERTIES)

            for decomp_analyzer in (
                "Decompiler Parameter ID",
                "Call Convention ID",
                "Decompiler Switch Analysis"
            ):
                analysis_opts.setBoolean(
                    decomp_analyzer,
                    False
                )
            
            flat_api.analyzeAll(prg)


            binary_functions_names = tuple(
                symbol.getName(True)
                for symbol in prg.getSymbolTable().getAllSymbols(True)
                if(
                    symbol.getSymbolType() == SymbolType.FUNCTION and
                    not symbol.isExternal()
                )
            )

            imported_functions_names = tuple(
                symbol.getName(True) # 'True' includes the DLL filename
                for symbol in prg.getSymbolTable().getAllSymbols(True)
                if(
                    symbol.getSymbolType() == SymbolType.FUNCTION and
                        symbol.isExternal()
                )
            )

            funcs_features = init_funcs_features_dict(
                binary_functions_names,
                imported_functions_names
            )

            called_funcs = defaultdict(set)

            prg_list = prg.getListing()
            block_model = BasicBlockModel(prg)

            binary_functions = names_to_functions(
                binary_functions_names,
                flat_api,
                prg
            )

            for curr_func, curr_func_name in zip(
                binary_functions, binary_functions_names
            ):

                funcs_features[curr_func_name]['num_local_vars'] = len(
                    curr_func.getLocalVariables()
                )

                # getParameterCount() returns a JInt value, which causes
                # problems with NetworkX later on.
                # By summing 0 to it, we convert it to a Python int.
                funcs_features[curr_func_name]['num_params'] = \
                    curr_func.getParameterCount() + 0
                
                for block in block_model.getCodeBlocksContaining(
                    curr_func.getBody(),
                    TaskMonitor.DUMMY
                ):
                    funcs_features[curr_func_name]['num_basic_blocks'] += 1
                    funcs_features[curr_func_name]['num_edges'] += \
                        block.getNumDestinations(TaskMonitor.DUMMY)

                instructions_iter = typing.cast(
                    typing.Iterable["Instruction"],
                    prg_list.getInstructions(
                        curr_func.getBody(),
                        True
                    )
                )
                for instr in instructions_iter:
                    funcs_features[curr_func_name]['num_instrs'] += 1
                    funcs_features[curr_func_name]['size'] += instr.getLength()

                    for ref in instr.getReferencesFrom():
                        # We consider jumps as well, since some packers might
                        # execute calls in a sneaky way; for instance,
                        # instead of CALL func:
                        # PUSH  ret_addr
                        # JMP   func
                        if( 
                            ref.getReferenceType().isCall() or
                            ref.getReferenceType().isJump()
                        ):
                            dest_symbol = flat_api.getSymbolAt(
                                ref.getToAddress()
                            )
                            if dest_symbol.getSymbolType() == SymbolType.FUNCTION:
                                called_func = dest_symbol.getName(True)

                                # Ignore recursive calls
                                if called_func != curr_func_name:
                                    called_funcs[curr_func_name].add(called_func)

                funcs_features[curr_func_name]['outdegree'] = len(
                    called_funcs[curr_func_name]
                )
    
    # Set indegrees, except for the external (imported) functions
    imported_functions_names = set(imported_functions_names)
    for curr_func_name in binary_functions_names:
        for called_func in called_funcs[curr_func_name] - imported_functions_names:
            funcs_features[called_func]['indegree'] += 1

    return funcs_features, called_funcs


if __name__ == '__main__':
    from sys import argv
    funcs_features, called_funcs = ghidra_extract_functions(argv[1])
    pass    # Place a BP here to explore the returned dicts in the debugger