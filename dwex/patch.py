import os
from struct import Struct
from ctypes import LittleEndianStructure, c_ubyte, c_uint, sizeof
from types import MethodType
from io import BytesIO

import elftools.dwarf.enums
import elftools.dwarf.dwarf_expr
import elftools.dwarf.locationlists
import elftools.elf.elffile
import elftools.elf.dynamic
import elftools.dwarf.dwarfinfo
import filebytes.mach_o
import filebytes.pe
from elftools.common.utils import struct_parse
from elftools.common.exceptions import DWARFError
from elftools.dwarf.descriptions import _DESCR_DW_CC
from elftools.dwarf.dwarfinfo import DebugSectionDescriptor
from elftools.elf.relocation import RelocationHandler
from elftools.elf.sections import Section
from elftools.elf.dynamic import Dynamic
from elftools.dwarf.locationlists import LocationLists, LocationListsPair
from elftools.construct.core import StaticField
from filebytes.mach_o import LSB_64_Section, MH, SectionData, LoadCommand, LoadCommandData, LC

# Good reference on DWARF extensions here:
# https://sourceware.org/elfutils/DwarfExtensions

# ELF reference:
# https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html

# LLVM extensions for heterogeneous debugging
# https://llvm.org/docs/AMDGPUDwarfExtensionsForHeterogeneousDebugging.html

#https://docs.hdoc.io/hdoc/llvm-project/e051F173385B23DEF.html

def monkeypatch():
    def get_location_list_at_offset(self, offset, die=None): # Fix for variable bitness in PS3
        if self.version >= 5 and die is None:
            raise DWARFError("For this binary, \"die\" needs to be provided")              
        self.stream.seek(offset, os.SEEK_SET)
        if die:
            self.structs = die.cu.structs
            self._max_addr = 2 ** (self.structs.address_size * 8) - 1
        return self._parse_location_list_from_stream_v5(die.cu) if self.version >= 5 else self._parse_location_list_from_stream()
    elftools.dwarf.locationlists.LocationLists.get_location_list_at_offset = get_location_list_at_offset

    # Raw location lists
    def get_location_list_at_offset_ex(self, offset, die=None):
        self.stream.seek(offset, os.SEEK_SET)
        if die:
            self.structs = die.cu.structs
            self._max_addr = 2 ** (self.structs.address_size * 8) - 1
        return [entry
            for entry
            in struct_parse(self.structs.Dwarf_loclists_entries, self.stream)]
    
    elftools.dwarf.locationlists.LocationLists.get_location_lists_at_offset_ex = get_location_list_at_offset_ex
    # Same for the pair object
    elftools.dwarf.locationlists.LocationListsPair.get_location_lists_at_offset_ex = lambda self, offset: self._loclists.get_location_lists_at_offset_ex(offset)

    # Fix for a corollary of 1683
    def get_range_list_at_offset(self, offset, cu=None):
        """ Get a range list at the given offset in the section.

            The cu argument is necessary if the ranges section is a
            DWARFv5 debug_rnglists one, and the target rangelist
            contains indirect encodings
        """
        if cu:
            self.structs = cu.structs
            self._max_addr = 2 ** (self.structs.address_size * 8) - 1            
        self.stream.seek(offset, os.SEEK_SET)
        return self._parse_range_list_from_stream(cu)
    def get_range_list_at_offset_ex(self, offset, cu=None):
        """Get a DWARF v5 range list, addresses and offsets unresolved,
        at the given offset in the section
        """
        if cu:
            self.structs = cu.structs
            self._max_addr = 2 ** (self.structs.address_size * 8) - 1            
        return struct_parse(self.structs.Dwarf_rnglists_entries, self.stream, offset)    
    elftools.dwarf.ranges.RangeLists.get_range_list_at_offset = get_range_list_at_offset
    elftools.dwarf.ranges.RangeLists.get_range_list_at_offset_ex = get_range_list_at_offset_ex

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

    # Fix for strtab link to NULL
    def DynamicSection_init(self, header, name, elffile):
        Section.__init__(self, header, name, elffile)
        stringtable = elffile.get_section(header['sh_link'], ('SHT_STRTAB', 'SHT_NOBITS', 'SHT_NULL'))
        Dynamic.__init__(self, self.stream, self.elffile, stringtable,
            self['sh_offset'], self['sh_type'] == 'SHT_NOBITS')
    elftools.elf.dynamic.DynamicSection.__init__ = DynamicSection_init

    # GNU opcodes - fix for #1740, except it's incompatible with the blob in the first crash
    elftools.dwarf.dwarf_expr.DW_OP_name2opcode['DW_OP_GNU_addr_index'] = 0xfb
    elftools.dwarf.dwarf_expr.DW_OP_name2opcode['DW_OP_GNU_const_index'] = 0xfc
    elftools.dwarf.dwarf_expr.DW_OP_name2opcode['DW_OP_GNU_variable_value'] = 0xfd

    elftools.dwarf.dwarf_expr.DW_OP_opcode2name[0xfb] = 'DW_OP_GNU_addr_index'
    elftools.dwarf.dwarf_expr.DW_OP_opcode2name[0xfc] = 'DW_OP_GNU_const_index'
    elftools.dwarf.dwarf_expr.DW_OP_opcode2name[0xfd] = 'DW_OP_GNU_variable_value'

    orig_init_dispatch_table = elftools.dwarf.dwarf_expr._init_dispatch_table
    def _init_dispatch_table(structs):
        dt = orig_init_dispatch_table(structs)
        f = lambda stream: [struct_parse(structs.the_Dwarf_uleb128, stream)]
        dt[0xfb] = f
        dt[0xfc] = f
        dt[0xfd] = f
        return dt
    elftools.dwarf.dwarf_expr._init_dispatch_table = _init_dispatch_table

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
