import pyghidra
pyghidra.start() # Otherwise we can't import ghidra modules
from ghidra.program.model.symbol import SymbolType      # type: ignore
from ghidra.program.model.listing import Program        # type: ignore

import tempfile
import hashlib
from collections import defaultdict, Counter
import typing

if typing.TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI       # type: ignore
    from ghidra.program.model.listing import Function       # type: ignore
    from ghidra.program.model.listing import Instruction    # type: ignore


# The minimum amount of instructions for a binary
# to be considered valid
NUM_INSTRUCTIONS_THRESHOLD = 20

# The minimum amount of instructions for the
# entry point to keep it as a separate function.
# Otherwise, if it calls a single function, merge it with the called function.
# This is done because many packers tend to have a single JMP instruction in
# the entry point, and this confuses the Graph Matching Network when it tries
# to classify graphs with a similar topology
#
# (e.g. tElock and Eronana graphs have only two nodes, with the entry point
# nodes being almost identical; unless both packers are included in the 
# training set, the net confuses the external packer with the one included
# in the training set).
NUM_INSTRUCTIONS_EP_THRESHOLD = 10

class InsufficientInstructionsError(Exception):
    def __init__(self, num_found: int, threshold: int):
        msg = (
            "Not enough instructions found\n"
            f"\tCount: {num_found}"
            f"\tThreshold: {threshold}"
        )
        super().__init__(msg)


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
            'stack',
            'arithmetic',
            'logical',
            'comparative',
            'uncond_jmp',
            'cond_jmp',
            'shift_rot',
            'mov',
            'lea',
            'call_ret',
            'string',
            'bit_flag',
            'other'
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

            binary_functions = names_to_functions(
                binary_functions_names,
                flat_api,
                prg
            )

            num_prg_instructions = 0
            other_instrs = []

            for curr_func, curr_func_name in zip(
                binary_functions, binary_functions_names
            ):

                instructions_iter = typing.cast(
                    typing.Iterable["Instruction"],
                    prg_list.getInstructions(
                        curr_func.getBody(),
                        True
                    )
                )
                for instr in instructions_iter:

                    num_prg_instructions += 1

                    for ref in instr.getReferencesFrom():
                        # For function calls we consider jumps as well,
                        # since some packers might execute calls
                        # in a sneaky way; for instance,
                        # instead of CALL func:
                        # PUSH  ret_addr
                        # JMP   func
                        refType = ref.getReferenceType()
                        if( 
                            refType.isCall() or
                            refType.isJump()
                        ):

                            dest_symbol = flat_api.getSymbolAt(
                                ref.getToAddress()
                            )

                            if dest_symbol.getSymbolType() == SymbolType.FUNCTION:
                                called_func = dest_symbol.getName(True)

                                # Ignore recursive calls
                                if called_func != curr_func_name:
                                    called_funcs[curr_func_name].add(called_func)

                    instr_mnemonic = instr \
                        .getMnemonicString() \
                        .casefold() \
                        .partition('.') [0] # e.g. 'scasb.repne' -> 'scasb'

                    match instr_mnemonic:
                        case    'push'  | 'pusha'   | 'pushf'   | \
                                          'pushad'  | 'pushfd'  | \
                                'pop'   | 'popa'    | 'popf'    | \
                                          'popad'   | 'popfd'   | \
                                'enter' | 'leave':
                            funcs_features[curr_func_name]['stack'] += 1
                        
                        case    'add'   | 'adc'     | 'inc'     | \
                                'sub'   | 'sbb'     | 'dec'     | \
                                'mul'   | 'imul'    | \
                                'div'   | 'idiv'    | \
                                'neg':
                            funcs_features[curr_func_name]['arithmetic'] += 1
                        
                        case    'and'   | 'or'      | 'xor'     | 'not':
                            funcs_features[curr_func_name]['logical'] += 1
                        
                        case    'cmp'   | 'test':
                            funcs_features[curr_func_name]['comparative'] += 1
                        
                        case    'je'    | 'jz'      | 'jne' | 'jnz' | \
                                'jg'    | 'jnle'    | 'jge' | 'jnl' | \
                                'jl'    | 'jnge'    | 'jle' | 'jng' | \
                                'ja'    | 'jnbe'    | 'jae' | 'jnb' | \
                                'jb'    | 'jnae'    | 'jbe' | 'jna' | \
                                'jo'    | 'jno'     | 'js'  | 'jns' | \
                                'jc'    | 'jnc'     | 'jp'  | 'jpe' | \
                                'jnp'   | 'jpo'     | \
                                'loop'  | 'loope'   | 'loopz' | \
                                'loopne'| 'loopnz'  | \
                                'jcxz'  | 'jecxz':
                            funcs_features[curr_func_name]['cond_jmp'] += 1
                        
                        case    'jmp':
                            funcs_features[curr_func_name]['uncond_jmp'] += 1
                        
                        case    'shl'   | 'sal'     | 'shr'     | 'sar' | \
                                'rol'   | 'ror'     | 'rcl'     | 'rcr':
                            funcs_features[curr_func_name]['shift_rot'] += 1 
                        
                        case    'mov'   | 'movsx'   | 'movsxd'  | 'movzx':
                            funcs_features[curr_func_name]['mov'] += 1
                        
                        case    'lea':
                            funcs_features[curr_func_name]['lea'] += 1

                        case    'call'  | 'ret':
                            funcs_features[curr_func_name]['call_ret'] += 1
                        
                        case    'movsb' | 'movsw'   | 'movsd'   | \
                                'lodsb' | 'lodsw'   | 'lodsd'   | \
                                'stosb' | 'stosw'   | 'stosd'   | \
                                'cmpsb' | 'cmpsw'   | 'cmpsd'   | \
                                'scasb' | 'scasw'   | 'scasd':
                            funcs_features[curr_func_name]['string'] += 1
                        
                        case    'bt'    | 'bts'     | 'btr'     | 'btc'     | \
                                'bsf'   | 'bsr'     | \
                                'stc'   | 'clc'     | 'cmc'     | \
                                'std'   | 'cld'     | 'sti'     | 'cli'     | \
                                'lahf'  | 'sahf'    | \
                                'setc'  | 'setb'    | 'setnae'  | 'setnc'   | \
                                                      'setae'   | 'setnb'   | \
                                'sete'  | 'setz'    | 'setne'   | 'setnz'   | \
                                'sets'  | 'setns'   | 'seto'    | 'setno'   | \
                                'setg'  | 'setge'   | 'setl'    | 'setle'   | \
                                'seta'  | 'setae'   | 'setb'    | 'setbe'   | \
                                'setp'  | 'setnp':
                                funcs_features[curr_func_name]['bit_flag'] += 1

                        case _:
                            funcs_features[curr_func_name]['other'] += 1
                            other_instrs.append(instr_mnemonic)

    if num_prg_instructions < NUM_INSTRUCTIONS_THRESHOLD:
        raise InsufficientInstructionsError(
            num_prg_instructions,
            NUM_INSTRUCTIONS_THRESHOLD
        )

    if other_instrs:
        unk_instrs = Counter(other_instrs)
        print("Instructions classified as 'other':")
        for instr, count in unk_instrs.most_common():
            print(f"\t{instr}: {count}")
    
    # Get the number of instructions in the entry point (if any)
    if 'entry' in funcs_features:
        num_ep_instrs = sum(
            instr_type_count
            for instr_type_count in funcs_features['entry'].values()
        )

        # if the entry point has a low amount of instructions, check
        # if it calls a single function and merge the features
        # of the entry point with the called function's features
        # (a lot of packers' stubs consist of a single JMP instruction).
        if (
            num_ep_instrs < NUM_INSTRUCTIONS_EP_THRESHOLD and
            len(called_funcs['entry']) == 1
        ):
            ep_called_func = next(iter(called_funcs['entry']))
            
            # The EP gets its called function's called funcs (if any);
            # otherwise, simply clear EP's set of called functions
            called_funcs['entry'] = (
                called_funcs.pop(ep_called_func)
                if ep_called_func in called_funcs
                else set()
            )
            
            # Merge features
            for instr in funcs_features['entry'].keys():
                funcs_features['entry'][instr] += \
                    funcs_features[ep_called_func][instr]

            # Delete the EP's called function's features
            del funcs_features[ep_called_func]

            # Replace any occurrences of ep_called_func with 'entry'
            for curr_cf_set in called_funcs.values():
                if ep_called_func in curr_cf_set:
                    curr_cf_set.remove(ep_called_func)
                    curr_cf_set.add('entry')

    return funcs_features, called_funcs


if __name__ == '__main__':
    from sys import argv
    funcs_features, called_funcs = ghidra_extract_functions(argv[1])
    pass    # Place a BP here to explore the returned dicts in the debugger