# coding=utf-8
# Copyright 2018 Sascha Schirra
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" A ND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from struct import pack as p
from .enum import Enum
from .binary import *
from binascii import hexlify
############# MachO General ######################

class MH(Enum):
    OBJECT = 0x1
    EXECUTE = 0x2
    FVMLIB = 0x3
    CORE = 0x4
    PRELOAD = 0x5
    DYLIB = 0x6
    DYLINKER = 0x7
    BUNDLE = 0x8
    DYLIB_STUB = 0x9
    DSYM = 0xa
    KEXT_BUNDLE = 0xb

class VM_PROT(Enum):
    READ = 0x1
    WRITE = 0x2
    EXEC = 0x4

    def shortString(self, perm):
        toReturn = ''
        toReturn += 'R' if perm & int(self.READ) > 0 else ' '
        toReturn += 'W' if perm & int(self.WRITE) > 0 else ' '
        toReturn += 'E' if perm & int(self.EXEC) > 0 else ' '

        return toReturn


class TypeFlags(Enum):
    MASK = 0xff000000
    ABI64 = 0x01000000


class CpuType(Enum):
    ANY = -1
    I386 = 7
    X86_64 = I386 | TypeFlags.ABI64
    MIPS = 8
    ARM = 12
    ARM64 = ARM | TypeFlags.ABI64
    SPARC = 14
    POWERPC = 18
    POWERPC64 = POWERPC | TypeFlags.ABI64
    LC_SEGMENT = 1
    LC_SEMGENT_64 = 0x19
    S_ATTR_SOME_INSTRUCTIONS = 0x400
    S_ATTR_PURE_INSTRUCTIONS = 0x80000000

class CpuSubTypeARM(Enum):
    ALL = 0
    V4T = 5
    V6 = 6
    V5 = 7
    XSCALE = 8
    V7 = 9
    V7S = 11
    V7K = 12
    V6M = 14
    V7M = 15
    V7EM = 16

class CpuSubTypeARM64(Enum):
    ALL = 0
    V8 = 1
    E = 2    

class SubTypeFlags(Enum):
    MASK = 0xff000000
    LIB64 = 0x80000000


class CPU_SUBTYPE_X86(Enum):
    X86 = 3
    X86_64 = X86 | SubTypeFlags.LIB64
    X86_64_H = 8
    I486 = 4
    I486SX = 0x84
    I586 = 5
    PENTPRO = 0x16
    PENTII_M3 = 0x36
    PENTII_M5 = 0x56
    CELERON = 0x67
    CELERON_MOBILE = 0x77
    PENTIUM_3_M = 0x18
    PENTIUM_3_XEON = 0x28
    PENTIUM_M = 0x09
    PENTIUM_4 = 0x0a
    PENTIUM_4_M = 0x1a
    ITANIUM = 0x0b
    ITANIUM_2 = 0x1b
    XEON = 0x0c
    XEON_MP = 0x1c


class LC(Enum):
    SEGMENT = 0x00000001
    SYMTAB = 0x00000002
    SYMSEG = 0x00000003
    THREAD = 0x00000004
    UNIXTHREAD = 0x00000005
    LOADFVMLIB = 0x00000006
    IDFVMLIB = 0x00000007
    IDENT = 0x00000008
    FVMFILE = 0x00000009
    PREPAGE = 0x0000000A
    DYSYMTAB = 0x0000000B
    LOAD_DYLIB = 0x0000000C
    ID_DYLIB = 0x0000000D
    LOAD_DYLINKER = 0x0000000E
    ID_DYLINKER = 0x0000000F
    PREBOUND_DYLIB = 0x00000010
    ROUTINES = 0x00000011
    SUB_FRAMEWORK = 0x00000012
    SUB_UMBRELLA = 0x00000013
    SUB_CLIENT = 0x00000014
    SUB_LIBRARY = 0x00000015
    TWOLEVEL_HINTS = 0x00000016
    PREBIND_CKSUM = 0x00000017
    LOAD_WEAK_DYLIB = 0x80000018
    SEGMENT_64 = 0x00000019
    ROUTINES_64 = 0x0000001A
    UUID = 0x0000001B
    RPATH = 0x8000001C
    CODE_SIGNATURE = 0x0000001D
    SEGMENT_SPLIT_INFO = 0x0000001E
    REEXPORT_DYLIB = 0x8000001F
    LAZY_LOAD_DYLIB = 0x00000020
    ENCRYPTION_INFO = 0x00000021
    DYLD_INFO = 0x00000022
    DYLD_INFO_ONLY = 0x80000022
    LOAD_UPWARD_DYLIB = 0x80000023
    VERSION_MIN_MACOSX = 0x00000024
    VERSION_MIN_IPHONEOS = 0x00000025
    FUNCTION_STARTS = 0x00000026
    DYLD_ENVIRONMENT = 0x00000027
    MAIN = 0x80000028
    DATA_IN_CODE = 0x00000029
    SOURCE_VERSION = 0x0000002A
    DYLIB_CODE_SIGN_DRS = 0x0000002B
    ENCRYPTION_INFO_64 = 0x0000002C
    LINKER_OPTIONS = 0x0000002D
    LINKER_OPTIMIZATION_HINT = 0x0000002E


class S_ATTR(Enum):
    SOME_INSTRUCTIONS = 0x00000400
    PURE_INSTRUCTIONS = 0x80000000

class LcStr(Union):
    _pack_ = 4
    _fields_ = [('offset', c_uint)]

class LoadCommand(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint)]


class UuidCommand(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('uuid', c_ubyte * 16)]

class TwoLevelHintsCommand(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('offset', c_uint),
                ('nhints', c_uint)]

class TwoLevelHint(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('isub_image', c_uint),
                ('itoc', c_uint)]

class Dylib(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('name', LcStr),
                ('timestamp', c_uint),
                ('current_version', c_uint),
                ('compatibility_version', c_uint),
                ]

class DylibCommand(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('dylib', Dylib),
                ]

class DylinkerCommand(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('name', LcStr)
                ]

########################### 32 BIT Structures ###########################

class LSB_32_MachHeader(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('magic', c_uint),
                ('cputype', c_uint),
                ('cpusubtype', c_uint),
                ('filetype', c_uint),
                ('ncmds', c_uint),
                ('sizeofcmds', c_uint),
                ('flags', c_uint)
                ]


class LSB_32_SegmentCommand(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('segname', c_char * 16),
                ('vmaddr', c_uint),
                ('vmsize', c_uint),
                ('fileoff', c_uint),
                ('filesize', c_uint),
                ('maxprot', c_uint),
                ('initprot', c_uint),
                ('nsects', c_uint),
                ('flags', c_uint)]


class LSB_32_Section(LittleEndianStructure):
    _pack_ = 4
    _fields_ = [('sectname', c_char * 16),
                ('segname', c_char * 16),
                ('addr', c_uint),
                ('size', c_uint),
                ('offset', c_uint),
                ('align', c_uint),
                ('reloff', c_uint),
                ('nreloc', c_uint),
                ('flags', c_uint),
                ('reserved1', c_uint),
                ('reserved2', c_uint)
                ]

class LSB_32(object):
    Section = LSB_32_Section
    SegmentCommand = LSB_32_SegmentCommand
    MachHeader = LSB_32_MachHeader

########################### 64 BIT Structures ###########################

class LSB_64_MachHeader(LittleEndianStructure):
    _pack_ = 8
    _fields_ = [('magic', c_uint),
                ('cputype', c_uint),
                ('cpusubtype', c_uint),
                ('filetype', c_uint),
                ('ncmds', c_uint),
                ('sizeofcmds', c_uint),
                ('flags', c_uint),
                ('reserved', c_uint),
                ]


class LSB_64_SegmentCommand(LittleEndianStructure):
    _pack_ = 8
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('segname', c_char * 16),
                ('vmaddr', c_ulonglong),
                ('vmsize', c_ulonglong),
                ('fileoff', c_ulonglong),
                ('filesize', c_ulonglong),
                ('maxprot', c_uint),
                ('initprot', c_uint),
                ('nsects', c_uint),
                ('flags', c_uint)]


class LSB_64_Section(LittleEndianStructure):
    _pack_ = 8
    _fields_ = [('sectname', c_char * 16),
                ('segname', c_char * 16),
                ('addr', c_ulonglong),
                ('size', c_ulonglong),
                ('offset', c_uint),
                ('align', c_uint),
                ('reloff', c_uint),
                ('nreloc', c_uint),
                ('flags', c_uint),
                ('reserved1', c_uint),
                ('reserved2', c_uint)
    ]

class LSB_64(object):
    Section = LSB_64_Section
    SegmentCommand = LSB_64_SegmentCommand
    MachHeader = LSB_64_MachHeader


############################# Fat/Universal ###########################

class FatHeader(BigEndianStructure):
    _pack_ = 4
    _fields_ = [('magic', c_uint),
                ('nfat_arch', c_uint)
    ]

class FatArch(BigEndianStructure):
    _pack_ = 4
    _fields_ = [('cputype', c_uint),
                ('cpusubtype', c_uint),
                ('offset', c_uint),
                ('size', c_uint),
                ('align', c_uint)
    ]

############################### Container #############################


class MachHeaderData(Container):
    """
    header = MachHeader
    """

class LoadCommandData(Container):
    """
    header = LoaderCommand
    bytes = bytes of the command bytearray
    raw = bytes of the command c_ubyte_array

    SegmentCommand
    sections = list of SectionData

    UuidCommand
    uuid = uuid (str)

    TwoLevelHintsCommand
    twoLevelHints = list of TwoLevelHintData

    DylibCommand
    name = name of dylib (str)

    DylinkerCommand
    name = name of dynamic linker
    """

class SectionData(Container):
    """
    header = Section

    """

class TwoLevelHintData(Container):
    """
    header = TwoLevelHint
    """

class MachO(Binary):

    def __init__(self, fileName, fileContent=None):
        super(MachO, self).__init__(fileName, fileContent)

        self.__fatArches = self._tryParseFat(self._bytes)
        if self.__fatArches:
            return

        self.__classes = self._getSuitableClasses(self._bytes)
        if not self.__classes:
            raise BinaryError('Bad architecture')

        self.__machHeader = self._parseMachHeader(self._bytes)
        self.__loadCommands = self._parseLoadCommands(self._bytes, self.machHeader)

    @property
    def _classes(self):
        return self.__classes

    @property
    def machHeader(self):
        assert not self.__fatArches
        return self.__machHeader

    @property
    def isFat(self):
        return self.__fatArches is not None

    @property
    def fatArches(self):
        assert self.__fatArches
        return self.__fatArches

    @property
    def loadCommands(self):
        assert not self.__fatArches
        return self.__loadCommands

    @property
    def entryPoint(self):
        return 0x0

    @property
    def imageBase(self):
        for loadCommand in self.loadCommands:
            if loadCommand.header.cmd == LC.SEGMENT or loadCommand.header.cmd == LC.SEGMENT_64:
                for section in loadCommand.sections:
                    if section.header.flags & S_ATTR.SOME_INSTRUCTIONS  or section.header.flags & S_ATTR.PURE_INSTRUCTIONS:
                        return section.header.addr - section.header.offset
        return 0x0

    @property
    def type(self):
        return 'MachO'

    def _getSuitableClasses(self, data):
        classes = None
        if data[7] == 0:
            classes = LSB_32
        elif data[7] == 1:
            classes = LSB_64

        return classes

    def _tryParseFat(self, data):
        header = FatHeader.from_buffer(data)
        if header.magic != 0xcafebabe:
            return None

        offset = sizeof(FatHeader)
        arches = []

        for i in range(header.nfat_arch):
            arch = FatArch.from_buffer(bytearray(data[offset:]))
            cputype = CpuType[arch.cputype]

            thin_data = bytearray(data[arch.offset : arch.offset+arch.size])
            thin = MachO('{}.{}'.format(self.fileName, cputype), thin_data)
            arches.append(thin)

            offset += sizeof(FatArch)

        return arches

    def _parseMachHeader(self, data):
        header = self._classes.MachHeader.from_buffer(data)

        if header.magic not in (0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe):
            raise BinaryError('No valid MachO file')

        return MachHeaderData(header=header)

    def _parseLoadCommands(self, data, machHeader):
        offset = sizeof(self._classes.MachHeader)
        load_commands = []
        for i in range(machHeader.header.ncmds):
            command = LoadCommand.from_buffer(data, offset)
            raw = (c_ubyte * command.cmdsize).from_buffer(data, offset)

            if command.cmd == LC.SEGMENT or command.cmd == LC.SEGMENT_64:
                command = self.__parseSegmentCommand(data, offset, raw)
            elif command.cmd == LC.UUID:
                command = self.__parseUuidCommand(data, offset, raw)
            elif command.cmd == LC.TWOLEVEL_HINTS:
                command = self.__parseTwoLevelHintCommand(data, offset, raw)
            elif command.cmd in (LC.ID_DYLIB, LC.LOAD_DYLIB, LC.LOAD_WEAK_DYLIB):
                command = self.__parseDylibCommand(data, offset, raw)
            elif command.cmd in (LC.ID_DYLINKER, LC.LOAD_DYLINKER):
                command = self.__parseDylibCommand(data, offset, raw)
            else:
                command = LoadCommandData(header=command)

            load_commands.append(command)

            offset += command.header.cmdsize

        return load_commands

    def __parseSegmentCommand(self, data, offset, raw):
        sc = self._classes.SegmentCommand.from_buffer(data, offset)
        sections = self.__parseSections(data, sc, offset+sizeof(self._classes.SegmentCommand))
        return LoadCommandData(header=sc, name=sc.segname.decode('ASCII'), sections=sections, bytes=bytearray(raw), raw=raw)

    def __parseUuidCommand(self, data, offset, raw):
        uc = UuidCommand.from_buffer(data, offset)
        return LoadCommandData(header=uc, uuid=hexlify(uc.uuid), bytes=bytearray(raw), raw=raw)

    def __parseTwoLevelHintCommand(self, data, offset, raw):
        tlhc = TwoLevelHintsCommand.from_buffer(data, offset)
        hints = self.__parseTwoLevelHints(data, tlhc)
        return LoadCommandData(header=tlhc, twoLevelHints=hints, bytes=bytearray(raw), raw=raw)

    def __parseTwoLevelHints(self, data, twoLevelHintCommand):
        offset = twoLevelHintCommand.offset
        hints = []
        for i in twoLevelHintCommand.nhints:
            tlh = TwoLevelHint.from_buffer(data, offset)
            hints.append(TwoLevelHintData(header=tlh))

        return hints

    def __parseDylibCommand(self, data, offset, raw):
        dc = DylibCommand.from_buffer(data, offset)
        name = get_str(raw, dc.dylib.name.offset)
        return LoadCommandData(header=dc, bytes=bytearray(raw), raw=raw, name=name)

    def __parseDylinkerCommand(self, data, offset, raw):
        dc = DylinkerCommand.from_buffer(data, offset)
        name = get_str(raw, dc.name.offset)
        return LoadCommandData(header=dc, bytes=bytearray(raw), raw=raw, name=name)

    def __parseSections(self, data, segment, offset):

        sections = []
        for i in range(segment.nsects):
            sec = self._classes.Section.from_buffer(data, offset)
            if self._classes.Section == LSB_64_Section:
                offset += 80
            else:
                offset += sizeof(self._classes.Section)

            if self.machHeader.header.filetype != MH.DSYM or segment.segname == b"__DWARF":
                raw = (c_ubyte * sec.size).from_buffer(data, sec.offset)
                bytes = bytearray(raw)
            else:
                raw = None
                bytes = None
            sections.append(SectionData(header=sec, name=sec.sectname.decode('ASCII'), bytes=bytes, raw=raw))

        return sections

    @classmethod
    def isSupportedContent(cls, fileContent):
        """Returns if the files are valid for this filetype"""
        magic = bytearray(fileContent)[:4]
        magics = (
            p('>I', 0xfeedface),
            p('>I', 0xfeedfacf),
            p('>I', 0xcafebabe),

            p('<I', 0xfeedface),
            p('<I', 0xfeedfacf),
            p('<I', 0xcafebabe),
        )
        return magic in magics
