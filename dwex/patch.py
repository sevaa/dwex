import elftools.dwarf.structs
import elftools.dwarf.die
import elftools.dwarf.compileunit
from elftools.construct import Struct, Enum, If, Switch
from elftools.dwarf.enums import *
from elftools.common.construct_utils import RepeatUntilExcluding
from elftools.common.utils import struct_parse
from elftools.dwarf.die import AttributeValue
from elftools.construct.adapters import ExprAdapter
from elftools.construct.macros import Array


# Fixes to pyelftools that are not in the released version yet
# Not sure about form_indirect, no binaries.
def monkeypatch():
    # Not sure about DW_FORM_indirect - need a test binary
    # This patches DW_FORM_data16
    def _create_dw_form_ex(self):
        self._create_dw_form_base()
        self.Dwarf_dw_form['DW_FORM_data16'] = Array(16, self.Dwarf_uint8(''))
            
    elftools.dwarf.structs.DWARFStructs._create_dw_form_base = elftools.dwarf.structs.DWARFStructs._create_dw_form
    elftools.dwarf.structs.DWARFStructs._create_dw_form = _create_dw_form_ex