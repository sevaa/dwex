import elftools.dwarf.structs
import elftools.dwarf.die
import elftools.dwarf.compileunit
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

    def iter_DIE_children_ex(self, die):
        """ Given a DIE, yields either its children, without null DIE list
            terminator, or nothing, if that DIE has no children.
            The null DIE terminator is saved in that DIE when iteration ended.
        """
        if not die.has_children:
            return

        # `cur_offset` tracks the stream offset of the next DIE to yield
        # as we iterate over our children,
        cur_offset = die.offset + die.size

        while True:
            child = self._get_cached_DIE(cur_offset)

            child.set_parent(die)

            if child.is_null():
                die._terminator = child
                return

            yield child

            if not child.has_children:
                cur_offset += child.size
            elif "DW_AT_sibling" in child.attributes:
                sibling = child.attributes["DW_AT_sibling"]
                if sibling.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref'):
                    cur_offset = sibling.value + self.cu_offset
                elif sibling.form == 'DW_FORM_ref_addr':
                    cur_offset = sibling.value
                else:
                    raise NotImplementedError('Sibling in form %s' % sibling.form)
            else:
                # If no DW_AT_sibling attribute is provided by the producer
                # then the whole child subtree must be parsed to find its next
                # sibling. There is one zero byte representing null DIE
                # terminating children list. It is used to locate child subtree
                # bounds.

                # If children are not parsed yet, this instruction will manage
                # to recursive call of this function which will result in
                # setting of `_terminator` attribute of the `child`.
                if child._terminator is None:
                    for _ in self.iter_DIE_children(child):
                        pass

                cur_offset = child._terminator.offset + child._terminator.size
    elftools.dwarf.compileunit.CompileUnit.iter_DIE_children = iter_DIE_children_ex