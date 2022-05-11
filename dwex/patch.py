import elftools.dwarf.structs
import elftools.dwarf.die
from elftools.construct import Struct, Enum, If
from elftools.dwarf.enums import *
from elftools.common.construct_utils import RepeatUntilExcluding
from elftools.common.utils import struct_parse
from elftools.dwarf.die import AttributeValue

# Fixes to pyelftools that are not in the released version yet
# #1490 for now - DW_FORM_implicit_const
def monkeypatch():
    def _create_abbrev_declaration_ex(self):
        self.Dwarf_abbrev_declaration = Struct('Dwarf_abbrev_entry',
            Enum(self.Dwarf_uleb128('tag'), **ENUM_DW_TAG),
            Enum(self.Dwarf_uint8('children_flag'), **ENUM_DW_CHILDREN),
            RepeatUntilExcluding(
                lambda obj, ctx:
                    obj.name == 'DW_AT_null' and obj.form == 'DW_FORM_null',
                Struct('attr_spec',
                    Enum(self.Dwarf_uleb128('name'), **ENUM_DW_AT),
                    Enum(self.Dwarf_uleb128('form'), **ENUM_DW_FORM),
                    If(lambda ctx: ctx['form'] == 'DW_FORM_implicit_const',
                        self.Dwarf_sleb128('value')))))
    elftools.dwarf.structs.DWARFStructs._create_abbrev_declaration = _create_abbrev_declaration_ex

    def _parse_DIE_ex(self):
        """ Parses the DIE info from the section, based on the abbreviation
            table of the CU
        """
        structs = self.cu.structs

        # A DIE begins with the abbreviation code. Read it and use it to
        # obtain the abbrev declaration for this DIE.
        # Note: here and elsewhere, preserve_stream_pos is used on operations
        # that manipulate the stream by reading data from it.
        self.abbrev_code = struct_parse(
            structs.Dwarf_uleb128(''), self.stream, self.offset)

        # This may be a null entry
        if self.abbrev_code == 0:
            self.size = self.stream.tell() - self.offset
            return

        abbrev_decl = self.cu.get_abbrev_table().get_abbrev(self.abbrev_code)
        self.tag = abbrev_decl['tag']
        self.has_children = abbrev_decl.has_children()

        # Guided by the attributes listed in the abbreviation declaration, parse
        # values from the stream.
        for spec in abbrev_decl['attr_spec']:
            form = spec.form
            name = spec.name
            attr_offset = self.stream.tell()
            # Special case here: the attribute value is stored in the attribute
            # definition in the abbreviation spec, not in the DIE itself.
            if form == 'DW_FORM_implicit_const':
                value = spec.value
                raw_value = value
            else:
                raw_value = struct_parse(structs.Dwarf_dw_form[form], self.stream)
                value = self._translate_attr_value(form, raw_value)
            self.attributes[name] = AttributeValue(
                name=name,
                form=form,
                value=value,
                raw_value=raw_value,
                offset=attr_offset)

        self.size = self.stream.tell() - self.offset

    elftools.dwarf.die.DIE._parse_DIE = _parse_DIE_ex