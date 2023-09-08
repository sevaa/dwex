import elftools.dwarf.enums
import elftools.dwarf.dwarf_expr
from elftools.common.utils import struct_parse
from elftools.common.exceptions import DWARFError

def monkeypatch():
    #https://docs.hdoc.io/hdoc/llvm-project/e051F173385B23DEF.html
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_LLVM_apinotes"] = 0x3e07
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_APPLE_objc_direct"] = 0x3fee
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_APPLE_sdk"] = 0x3fef

    # Wasmloc: monkeypatch for #1589
    elftools.dwarf.dwarf_expr.DW_OP_name2opcode["DW_OP_WASM_location"] = 0xed
    old_init_dispatch_table = elftools.dwarf.dwarf_expr._init_dispatch_table
    def _init_dispatch_table_patch(structs):
        def parse_wasmloc():
            def parse(stream):
                op = struct_parse(structs.Dwarf_uint8(''), stream)
                if op in (0, 1, 2):
                    return [op, struct_parse(structs.Dwarf_uleb128(''), stream)]
                elif op == 3:
                    return [op, struct_parse(structs.Dwarf_uint32(''), stream)]
                else:
                    raise DWARFError("Unknown operation code in DW_OP_WASM_location: %d" % (op,))
            return parse
        table = old_init_dispatch_table(structs)
        table[0xed] = parse_wasmloc()
        return table
    
    elftools.dwarf.dwarf_expr._init_dispatch_table = _init_dispatch_table_patch
