import os
from struct import Struct
from ctypes import LittleEndianStructure, c_ubyte, c_uint, sizeof
from types import MethodType
from io import BytesIO

import elftools.dwarf.enums
import elftools.dwarf.dwarf_expr
import elftools.dwarf.locationlists
import elftools.elf.elffile
import elftools.dwarf.dwarfinfo
import filebytes.mach_o
import filebytes.pe
from elftools.common.utils import struct_parse
from elftools.common.exceptions import DWARFError
from elftools.dwarf.descriptions import _DESCR_DW_CC
from elftools.dwarf.dwarfinfo import DebugSectionDescriptor
from elftools.elf.relocation import RelocationHandler
from elftools.dwarf.locationlists import LocationLists, LocationListsPair
from elftools.construct.core import StaticField
from filebytes.mach_o import LSB_64_Section, MH, SectionData, LoadCommand, LoadCommandData, LC

# Good reference on DWARF extensions here:
# https://sourceware.org/elfutils/DwarfExtensions

# ELF reference:
# https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html

# LLVM extensions for heterogeneous debugging
# https://llvm.org/docs/AMDGPUDwarfExtensionsForHeterogeneousDebugging.html

_UBInt24_packer = Struct(">BH")
_ULInt24_packer = Struct("<HB")

class UBInt24(StaticField):
    """unsigned, big endian 24-bit integer"""
    def __init__(self, name):
        StaticField.__init__(self, name, 3)

    def _parse(self, stream, context):
        global _UBInt24_packer
        (h, l) = _UBInt24_packer.unpack(StaticField._parse(self, stream, context))
        return l | (h << 16)
    
    def _build(self, obj, stream, context):
        global _UBInt24_packer
        StaticField._build(self, _UBInt24_packer.pack(obj >> 16, obj & 0xFFFF), stream, context)

class ULInt24(StaticField):
    """unsigned, little endian 24-bit integer"""
    def __init__(self, name):
        StaticField.__init__(self, name, 3)

    def _parse(self, stream, context):
        global _ULInt24_packer
        (l, h) = _ULInt24_packer.unpack(StaticField._parse(self, stream, context))
        return l | (h << 16)
    
    def _build(self, obj, stream, context):
        global _ULInt24_packer
        StaticField._build(self, _ULInt24_packer.pack(obj & 0xFFFF, obj >> 16), stream, context)


def monkeypatch():
    #https://docs.hdoc.io/hdoc/llvm-project/e051F173385B23DEF.html
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_LLVM_apinotes"] = 0x3e07
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_APPLE_objc_direct"] = 0x3fee
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_APPLE_sdk"] = 0x3fef

    # Wasmloc: monkeypatch for #1589
    elftools.dwarf.dwarf_expr.DW_OP_name2opcode["DW_OP_WASM_location"] = 0xed
    elftools.dwarf.dwarf_expr.DW_OP_opcode2name[0xed] = "DW_OP_WASM_location"
    elftools.dwarf.dwarf_expr.DW_OP_name2opcode['DW_OP_GNU_uninit'] = 0xf0
    elftools.dwarf.dwarf_expr.DW_OP_opcode2name[0xf0] = 'DW_OP_GNU_uninit'
    old_init_dispatch_table = elftools.dwarf.dwarf_expr._init_dispatch_table
    def _init_dispatch_table_patch(structs):
        def parse_wasmloc():
            def parse(stream):
                op = struct_parse(structs.Dwarf_uint8(''), stream)
                if 0 <= op <= 2:
                    return [op, struct_parse(structs.Dwarf_uleb128(''), stream)]
                elif op == 3:
                    return [op, struct_parse(structs.Dwarf_uint32(''), stream)]
                else:
                    raise DWARFError("Unknown operation code in DW_OP_WASM_location: %d" % (op,))
            return parse
        #wasmloc patch
        table = old_init_dispatch_table(structs)
        table[0xed] = parse_wasmloc()
        # GNU_uninit
        table[0xf0] = lambda s: []
        return table
    
    elftools.dwarf.dwarf_expr._init_dispatch_table = _init_dispatch_table_patch

    # Fix for 1613 and other bogus loclist/bogus expr bugs
    def _attribute_is_constant(attr, dwarf_version):
        return (((dwarf_version >= 3 and attr.name == 'DW_AT_data_member_location') or
                (attr.name in ('DW_AT_upper_bound', 'DW_AT_count'))) and
            attr.form in ('DW_FORM_data1', 'DW_FORM_data2', 'DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sdata', 'DW_FORM_udata', 'DW_FORM_implicit_const'))
    
    def _attribute_has_loc_list(cls, attr, dwarf_version):
        return (((dwarf_version < 4 and
                 attr.form in ('DW_FORM_data1', 'DW_FORM_data2', 'DW_FORM_data4', 'DW_FORM_data8') and
                 not attr.name == 'DW_AT_const_value') or
                attr.form in ('DW_FORM_sec_offset', 'DW_FORM_loclistx')) and
                not _attribute_is_constant(attr, dwarf_version))
    
    def _attribute_is_loclistptr_class(cls, attr):
        return (attr.name in ( 'DW_AT_location', 'DW_AT_string_length',
                               'DW_AT_const_value', 'DW_AT_return_addr',
                               'DW_AT_data_member_location',
                               'DW_AT_frame_base', 'DW_AT_segment',
                               'DW_AT_static_link', 'DW_AT_use_location',
                               'DW_AT_vtable_elem_location',
                               'DW_AT_call_value',
                               'DW_AT_GNU_call_site_value',
                               'DW_AT_GNU_call_site_target',
                               'DW_AT_GNU_call_site_data_value',
                               'DW_AT_call_target',
                               'DW_AT_call_target_clobbered',
                               'DW_AT_call_data_location',
                               'DW_AT_call_data_value',
                               'DW_AT_upper_bound',
                               'DW_AT_count'))
    elftools.dwarf.locationlists.LocationParser._attribute_has_loc_list = MethodType(_attribute_has_loc_list, elftools.dwarf.locationlists.LocationParser)
    elftools.dwarf.locationlists.LocationParser._attribute_is_loclistptr_class = MethodType(_attribute_is_loclistptr_class, elftools.dwarf.locationlists.LocationParser)

    # Raw location lists
    def get_location_list_at_offset_ex(self, offset):
        self.stream.seek(offset, os.SEEK_SET)
        return [entry
            for entry
            in struct_parse(self.structs.Dwarf_loclists_entries, self.stream)]
    
    elftools.dwarf.locationlists.LocationLists.get_location_lists_at_offset_ex = get_location_list_at_offset_ex
    # Same for the pair object
    elftools.dwarf.locationlists.LocationListsPair.get_location_lists_at_offset_ex = lambda self, offset: self._loclists.get_location_lists_at_offset_ex(offset)

    # Rangelist entry translate with mixed V4/V5
    def translate_v5_entry(self, entry, cu):
        return self._rnglists.translate_v5_entry(entry, cu)
    elftools.dwarf.ranges.RangeListsPair.translate_v5_entry = translate_v5_entry

    # DWARF5 calling convention codes
    _DESCR_DW_CC[4] = '(pass by ref)'
    _DESCR_DW_CC[5] = '(pass by value)'

    # Monkeypatch for bogus XC16 binaries (see pyelftools' #518)
    def _read_dwarf_section(self, section, relocate_dwarf_sections):
        # Patch for the XC16 compiler; see pyelftools' #518
        # Vendor flag EF_PIC30_NO_PHANTOM_BYTE: clear means drop every odd byte
        has_phantom_bytes = self['e_machine'] == 'EM_DSPIC30F' and (self['e_flags'] & 0x80000000) == 0

        # The section data is read into a new stream, for processing
        section_stream = BytesIO()
        section_data = section.data()
        section_stream.write(section_data[::2] if has_phantom_bytes else section_data)

        if relocate_dwarf_sections:
            reloc_handler = RelocationHandler(self)
            reloc_section = reloc_handler.find_relocations_for_section(section)
            if reloc_section is not None:
                if has_phantom_bytes:
                    # No guidance how should the relocation work - before or after the odd byte skip
                    raise DWARFError("This binary has relocations in the DWARF sections, currently not supported. Let the author of DWARF Explorer know.")
                else:
                    reloc_handler.apply_section_relocations(
                        section_stream, reloc_section)

        return DebugSectionDescriptor(
                stream=section_stream,
                name=section.name,
                global_offset=section['sh_offset'],
                size=section.data_size//2 if has_phantom_bytes else section.data_size,
                address=section['sh_addr'])
    
    elftools.elf.elffile.ELFFile._read_dwarf_section = _read_dwarf_section

    # Fix for #1572, also for eliben/pyelftools#519
    def location_lists(self):
        """ Get a LocationLists object representing the .debug_loc/debug_loclists section of
            the DWARF data, or None if this section doesn't exist.
            If both sections exist, it returns a LocationListsPair.
        """
        if self.debug_loclists_sec and self.debug_loc_sec is None:
            return LocationLists(self.debug_loclists_sec.stream, self.structs, 5, self)
        elif self.debug_loc_sec and self.debug_loclists_sec is None:
            return LocationLists(self.debug_loc_sec.stream, self.structs, 4, self)
        elif self.debug_loc_sec and self.debug_loclists_sec:
            return LocationListsPair(self.debug_loc_sec.stream, self.debug_loclists_sec.stream, self.structs, self)
        else:
            return None
        
    elftools.dwarf.dwarfinfo.DWARFInfo.location_lists = location_lists

    # Fix for struct building for adding Int24, #1614
    old_create_structs = elftools.dwarf.dwarfinfo.DWARFStructs._create_structs
    def _create_structs(self):
        old_create_structs(self)
        if self.little_endian:
            self.Dwarf_uint24 = ULInt24
        else:
            self.Dwarf_uint24 = UBInt24
        self.Dwarf_dw_form['DW_FORM_strx3'] = self.Dwarf_uint24('')
        self.Dwarf_dw_form['DW_FORM_addrx3'] = self.Dwarf_uint24('')
    elftools.dwarf.dwarfinfo.DWARFStructs._create_structs = _create_structs

    # Fix for #1588
    elftools.dwarf.enums.ENUM_DW_LNCT['DW_LNCT_LLVM_source'] = 0x2001
    elftools.dwarf.enums.ENUM_DW_LNCT['DW_LNCT_LLVM_is_MD5'] = 0x2002

    # Short out import directory parsing for now
    filebytes.pe.PE._parseDataDirectory = lambda self,a,b,c: None

    # Expand the logic in DSYM bundle loading to load the unwind sections too
    def __parseSections(self, data, segment, offset):
        sections = []
        for i in range(segment.nsects):
            sec = self._classes.Section.from_buffer(data, offset)
            if self._classes.Section == LSB_64_Section:
                offset += 80
            else:
                offset += sizeof(self._classes.Section)

            if sec.offset > 0:
                raw = (c_ubyte * sec.size).from_buffer(data, sec.offset)
                bytes = bytearray(raw)
            else:
                raw = None
                bytes = None
            sections.append(SectionData(header=sec, name=sec.sectname.decode('ASCII'), bytes=bytes, raw=raw))

        return sections
    
    filebytes.mach_o.MachO._MachO__parseSections = __parseSections

    # SYMTAB parsing - LE only, but filebytes is broken anyway in that regard
    class SymtabCommand(LittleEndianStructure):
        _pack_ = 4
        _fields_ = [('cmd', c_uint),
            ('cmdsize', c_uint),
            ('symbols_offset', c_uint),
            ('nsymbols', c_uint),
            ('strings_offset', c_uint),
            ('nstrings', c_uint)]
        
    def _parseLoadCommands(self, data, machHeader):
        offset = sizeof(self._classes.MachHeader)
        load_commands = []
        for i in range(machHeader.header.ncmds):
            command = LoadCommand.from_buffer(data, offset)
            raw = (c_ubyte * command.cmdsize).from_buffer(data, offset)

            if command.cmd == LC.SEGMENT or command.cmd == LC.SEGMENT_64:
                command = self._MachO__parseSegmentCommand(data, offset, raw)
            elif command.cmd == LC.UUID:
                command = self._MachO__parseUuidCommand(data, offset, raw)
            elif command.cmd == LC.TWOLEVEL_HINTS:
                command = self._MachO__parseTwoLevelHintCommand(data, offset, raw)
            elif command.cmd in (LC.ID_DYLIB, LC.LOAD_DYLIB, LC.LOAD_WEAK_DYLIB):
                command = self._MachO__parseDylibCommand(data, offset, raw)
            elif command.cmd in (LC.ID_DYLINKER, LC.LOAD_DYLINKER):
                command = self._MachO__parseDylibCommand(data, offset, raw)
            elif command.cmd == LC.SYMTAB:
                uc = SymtabCommand.from_buffer(data, offset)
                command = LoadCommandData(header=uc)
            else:
                command = LoadCommandData(header=command)

            load_commands.append(command)

            offset += command.header.cmdsize

        return load_commands
    filebytes.mach_o.MachO._parseLoadCommands = _parseLoadCommands
