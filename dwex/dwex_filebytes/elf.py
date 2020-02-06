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


from .enum import Enum
from .binary import *

####################### Constants ############################

class ET(Enum):
    NONE = 0x0
    REL = 0x1
    EXEC = 0x2
    DYN = 0x3
    CORE = 0x4
    LOOS = 0xfe00
    HIOS = 0xfeff
    LOPROC = 0xff00
    HIPROC = 0xffff


class EM(Enum):
    NONE = 0  # No machine
    M32 = 1  # AT&T WE 32100
    SPARC = 2  # SPARC
    INTEL_386 = 3  # Intel 80386
    MOTOROLA_68k = 4  # Motorola 68000
    MOTOROLA_88K = 5  # Motorola 88000
    INTEL_80860 = 7  # Intel 80860
    MIPS = 8  # MIPS RS3000
    S370 = 9
    MIPS_RS3_LE = 10

    PARISC = 15
    VPP500 = 17
    SPARC32PLUS = 18
    INTEL_80960 = 19
    PPC = 20
    PPC64 = 21
    S390 = 22

    V800 = 36
    FR20 = 37
    RH32 = 38
    RCE = 39
    ARM = 40
    FAKE_ALPHA = 41
    SH = 42
    SPARCV9 = 43
    TRICORE = 44
    ARC = 45
    H8_300 = 46
    H8_300H = 47
    H8S = 48
    H8_500 = 49
    IA_64 = 50
    MIPS_X = 51
    COLDFIRE = 52
    MOTOROLA_68HC12 = 53
    MMA = 54
    PCP = 55
    NCPU = 56
    NDR1 = 57
    STARCORE = 58
    ME16 = 59
    ST100 = 60
    TINYJ = 61
    X86_64 = 62
    FX66 = 66
    ST9PLUS = 67
    ST7 = 68
    MOTOROLA_68HC16 = 69
    MOTOROLA_68HC11 = 70
    MOTOROLA_68HC08 = 71
    MOTOROLA_68HC05 = 72
    SVX = 73
    ST19 = 74
    VAX = 75
    CRIS = 76
    JAVELIN = 77
    FIREPATH = 78
    ZSP = 79
    MMIX = 80
    HUANY = 81
    PRISM = 82
    AVR = 83
    FR30 = 84
    D10V = 85
    D30V = 86
    V850 = 87
    M32R = 88
    MN10300 = 89
    MN10200 = 90
    PJ = 91
    OPENRISC = 92
    ARC_A5 = 93
    XTENSA = 94
    NUM = 95
    ARM64 = 183


class EI(Enum):
    MAG0 = 0x0
    MAG1 = 0x1
    MAG2 = 0x2
    MAG3 = 0x3
    CLASS = 0x4
    DATA = 0x5
    VERSION = 0x6
    OSABI = 0x7
    ABIVERSION = 0x8
    PAD = 0x9
    NIDENT = 0xf


class ELFOSABI(Enum):
    SYSV = 0
    HPUX = 1
    STANDALONE = 255


class ELFCLASS(Enum):
    NONE = 0
    BITS_32 = 1
    BITS_64 = 2


class ELFDATA(Enum):
    NONE = 0
    LSB = 1
    MSB = 2


class SHN(Enum):
    UNDEF = 0
    LOPROC = 0xff00
    HIPROC = 0xff1f
    LOOS = 0xff20
    HIOS = 0xff3f
    ABS = 0xfff1
    COMMON = 0xfff2
    HIRESERVE = 0xffff

class SHF(Enum):
    WRITE = 0x1
    ALLOC = 0x2
    EXECINSTR = 0x4
    MASKPROC = 0xf0000000


class SHT(Enum):
    NULL = 0x0
    PROGBITS = 0x1
    SYMTAB = 0x2
    STRTAB = 0x3
    RELA = 0x4
    HASH = 0x5
    DYNAMIC = 0x6
    NOTE = 0x7
    NOBITS = 0x8
    REL = 0x9
    SHLIB = 0xa
    DYNSYM = 0xb
    INIT_ARRAY = 0xe
    FINI_ARRAY = 0xf
    PREINIT_ARRAY = 0x10
    GROUP = 0x11
    SYMTAB_SHNDX = 0x12
    NUM = 0x13
    LOOS = 0x60000000
    GNU_HASH = 0x6ffffff6
    GNU_LIBLIST = 0x6ffffff7
    CHECKSUM = 0x6ffffff8
    LOSUNW = 0x6ffffffa
    SUNW_COMDAT = 0x6ffffffb
    SUNW_syminfo = 0x6ffffffc
    GNU_verdef = 0x6ffffffd
    GNU_verneed = 0x6ffffffe
    HIOS = 0x6fffffff
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff
    LOUSER = 0x80000000
    HIUSER = 0x8fffffff


class STT(Enum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6
    NUM = 7
    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15


class STB(Enum):

    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    NUM = 3
    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15

class STV(Enum):
    DEFAULT = 0
    INTERNAL = 1
    HIDDEN = 2
    PROTECTED = 3
    EXPORTED = 4
    SINGLETON = 5
    ELIMINATE = 6



class PT(Enum):
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6
    TLS = 7
    NUM = 8
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff

    GNU_EH_FRAME = 0x6474e550
    GNU_STACK = 0x6474e551
    GNU_RELRO = 0x6474e552


class R_386(Enum):
    NONE = 0
    R_32 = 1
    PC32 = 2
    GOT32 = 3
    PLT32 = 4
    COPY = 5
    GLOB_DAT = 6
    JMP_SLOT = 7
    RELATIVE = 8
    GOTOFF = 9
    GOTPC = 10

    TLS_TPOFF = 14
    TLS_IE = 15
    TLS_GOTIE = 16
    TLS_LE = 17
    TLS_GD = 18
    TLS_LDM = 19
    R16 = 20
    PC16 = 21
    R8 = 22
    PC8 = 23
    TLS_GD_32 = 24
    TLS_GD_PUSH = 25
    TLS_GD_CALL = 26
    TLS_GD_POP = 27
    TLS_LDM_32 = 28
    TLS_LDM_PUSH = 29
    TLS_LDM_CALL = 30
    TLS_LDM_POP = 31
    TLS_LDO_32 = 32
    TLS_IE_32 = 33
    TLS_LE_32 = 34
    TLS_DTPMOD32 = 35
    TLS_DTPOFF32 = 36
    TLS_TPOFF32 = 37
    NUM = 38


class PF(Enum):

    READ = 4
    WRITE = 2
    EXEC = 1

    def shortString(self, perm):
        toReturn = ''
        toReturn += 'R' if perm & int(self.READ) > 0 else ' '
        toReturn += 'W' if perm & int(self.WRITE) > 0 else ' '
        toReturn += 'E' if perm & int(self.EXEC) > 0 else ' '

        return toReturn

class DT(Enum):
    NULL = 0
    NEEDED = 1
    PLTRELSZ = 2
    PLTGOT = 3
    HASH = 4
    STRTAB = 5
    SYMTAB = 6
    RELA = 7
    RELASZ = 8
    RELAENT = 9
    STRSZ = 10
    SYMENT = 11
    INIT = 12
    FINI = 13
    SONAME = 14
    RPATH = 15
    SYMBOLIC = 16
    REL = 17
    RELSZ = 18
    RELENT = 19
    PLTREL = 20
    DEBUG = 21
    TEXTREL = 22
    JMPREL = 23
    BIND_NOW = 24
    INIT_ARRAY = 25
    FINI_ARRAY = 26
    INIT_ARRAYSZ = 27
    FINI_ARRAYSZ = 28
    RUNPATH = 29
    FLAGS = 30
    ENCODING = 31
    PREINIT_ARRAY = 32
    PREINIT_ARRAYSZ = 33
    MAXPOSTAGS = 34
    LOOS = 0x6000000d
    #SUNW_AUXILIARY = 0x6000000d
    SUNW_RTLDINF = 0x6000000e
    #SUNW_FILTER = 0x6000000e
    SUNW_CAP = 0x60000010
    SUNW_SYMTAB = 0x60000011
    SUNW_SYMSZ = 0x60000012
    SUNW_ENCODING = 0x60000013
    #SUNW_SORTENT = 0x60000013
    SUNW_SYMSORT = 0x60000014
    SUNW_SYMSORTSZ = 0x60000015
    SUNW_TLSSORT = 0x60000016
    SUNW_TLSSORTSZ = 0x60000017
    SUNW_CAPINFO = 0x60000018
    SUNW_STRPAD = 0x60000019
    SUNW_CAPCHAIN = 0x6000001a
    SUNW_LDMACH = 0x6000001b
    SUNW_CAPCHAINENT = 0x6000001d
    SUNW_CAPCHAINSZ = 0x6000001f
    HIOS = 0x6ffff000
    VALRNGLO = 0x6ffffd00
    CHECKSUM = 0x6ffffdf8
    PLTPADSZ = 0x6ffffdf9
    MOVEENT = 0x6ffffdfa
    MOVESZ = 0x6ffffdfb
    POSFLAG_1 = 0x6ffffdfd
    SYMINSZ = 0x6ffffdfe
    SYMINENT = 0x6ffffdff
    #VALRNGHI = 0x6ffffdff
    ADDRRNGLO = 0x6ffffe00
    GNU_HASH = 0x6ffffef5
    TLSDESC_PLT = 0x6ffffef6
    TLSDESC_GOT  = 0x6ffffef7
    GNU_CONFLICT = 0x6ffffef8
    GNU_LIBLIST = 0x6ffffef9
    CONFIG = 0x6ffffefa
    DEPAUDIT = 0x6ffffefb
    AUDIT = 0x6ffffefc
    PLTPAD = 0x6ffffefd
    MOVETAB = 0x6ffffefe
    SYMINFO = 0x6ffffeff
    #ADDRRNGHI = 0x6ffffeff
    VERSYM = 0x6ffffff0
    RELACOUNT = 0x6ffffff9
    RELCOUNT = 0x6ffffffa
    FLAGS_1 = 0x6ffffffb
    VERDEF = 0x6ffffffc
    VERDEFNUM = 0x6ffffffd
    VERNEED = 0x6ffffffe
    VERNEEDNUM = 0x6fffffff
    LOPROC = 0x70000000
    SPARC_REGISTER = 0x70000001
    AUXILIARY = 0x7ffffffd
    USED = 0x7ffffffe
    #FILTER = 0x7fffffff
    HIPROC = 0x7fffffff

########################### LSB 32 BIT Structures ###########################

LSB_32_R_SYM = lambda i: i >> 8
LSB_32_R_TYPE = lambda i: i & 0xff


class LSB_32_EHDR(LittleEndianStructure):
    _fields_ = [('e_ident', c_ubyte * 16),
                ('e_type', c_ushort),
                ('e_machine', c_ushort),
                ('e_version', c_uint),
                ('e_entry', c_uint),
                ('e_phoff', c_uint),
                ('e_shoff', c_uint),
                ('e_flags', c_uint),
                ('e_ehsize', c_ushort),
                ('e_phentsize', c_ushort),
                ('e_phnum', c_ushort),
                ('e_shentsize', c_ushort),
                ('e_shnum', c_ushort),
                ('e_shstrndx', c_ushort)]


class LSB_32_SHDR(LittleEndianStructure):
    _fields_ = [('sh_name', c_uint),
                ('sh_type', c_uint),
                ('sh_flags', c_uint),
                ('sh_addr', c_uint),
                ('sh_offset', c_uint),
                ('sh_size', c_uint),
                ('sh_link', c_uint),
                ('sh_info', c_uint),
                ('sh_addralign', c_uint),
                ('sh_entsize', c_uint)
                ]


class LSB_32_SYM(LittleEndianStructure):
    _fields_ = [('st_name', c_uint),
                ('st_value', c_uint),
                ('st_size', c_uint),
                ('st_info', c_ubyte),
                ('st_other', c_ubyte),
                ('st_shndx', c_ushort)
                ]


class LSB_32_REL(LittleEndianStructure):
    _fields_ = [('r_offset', c_uint),
                ('r_info', c_uint)]


class LSB_32_RELA(LittleEndianStructure):
    _fields_ = [('r_offset', c_uint),
                ('r_info', c_uint),
                ('r_addend', c_int)
                ]


class LSB_32_PHDR(LittleEndianStructure):
    _fields_ = [('p_type', c_uint),
                ('p_offset', c_uint),
                ('p_vaddr', c_uint),
                ('p_paddr', c_uint),
                ('p_filesz', c_uint),
                ('p_memsz', c_uint),
                ('p_flags', c_uint),
                ('p_align', c_uint)
                ]

class LSB_32_DYN(LittleEndianStructure):
    _fields_ = [('d_tag', c_uint),
                ('d_un', c_uint)
                ]

class LSB_32():
    PHDR = LSB_32_PHDR
    EHDR = LSB_32_EHDR
    SHDR = LSB_32_SHDR
    REL = LSB_32_REL
    RELA = LSB_32_RELA
    SYM = LSB_32_SYM
    DYN = LSB_32_DYN
    R_SYM = staticmethod(LSB_32_R_SYM)
    R_TYPE = staticmethod(LSB_32_R_TYPE)

########################### MSB 32 BIT Structures ###########################

MSB_32_R_SYM = lambda i: i >> 8
MSB_32_R_TYPE = lambda i: i & 0xff


class MSB_32_EHDR(BigEndianStructure):
    _fields_ = [('e_ident', c_ubyte * 16),
                ('e_type', c_ushort),
                ('e_machine', c_ushort),
                ('e_version', c_uint),
                ('e_entry', c_uint),
                ('e_phoff', c_uint),
                ('e_shoff', c_uint),
                ('e_flags', c_uint),
                ('e_ehsize', c_ushort),
                ('e_phentsize', c_ushort),
                ('e_phnum', c_ushort),
                ('e_shentsize', c_ushort),
                ('e_shnum', c_ushort),
                ('e_shstrndx', c_ushort)]


class MSB_32_SHDR(BigEndianStructure):
    _fields_ = [('sh_name', c_uint),
                ('sh_type', c_uint),
                ('sh_flags', c_uint),
                ('sh_addr', c_uint),
                ('sh_offset', c_uint),
                ('sh_size', c_uint),
                ('sh_link', c_uint),
                ('sh_info', c_uint),
                ('sh_addralign', c_uint),
                ('sh_entsize', c_uint)
                ]


class MSB_32_SYM(BigEndianStructure):
    _fields_ = [('st_name', c_uint),
                ('st_value', c_uint),
                ('st_size', c_uint),
                ('st_info', c_ubyte),
                ('st_other', c_ubyte),
                ('st_shndx', c_ushort)
                ]


class MSB_32_REL(BigEndianStructure):
    _fields_ = [('r_offset', c_uint),
                ('r_info', c_uint)]


class MSB_32_RELA(BigEndianStructure):
    _fields_ = [('r_offset', c_uint),
                ('r_info', c_uint),
                ('r_addend', c_int)
                ]


class MSB_32_PHDR(BigEndianStructure):
    _fields_ = [('p_type', c_uint),
                ('p_offset', c_uint),
                ('p_vaddr', c_uint),
                ('p_paddr', c_uint),
                ('p_filesz', c_uint),
                ('p_memsz', c_uint),
                ('p_flags', c_uint),
                ('p_align', c_uint)
                ]

class MSB_32_DYN(BigEndianStructure):
    _fields_ = [('d_tag', c_uint),
                ('d_un', c_uint)
                ]

class MSB_32():
    PHDR = MSB_32_PHDR
    EHDR = MSB_32_EHDR
    SHDR = MSB_32_SHDR
    REL = MSB_32_REL
    RELA = MSB_32_RELA
    SYM = MSB_32_SYM
    DYN = MSB_32_DYN
    R_SYM = staticmethod(MSB_32_R_SYM)
    R_TYPE = staticmethod(MSB_32_R_TYPE)

########################### 64 BIT Types ###########################

Elf64_Addr = c_ulonglong
Elf64_Off = c_ulonglong
Elf64_Half = c_ushort
Elf64_Word = c_uint
Elf64_Sword = c_int
Elf64_Xword = c_ulonglong
Elf64_Sxword = c_longlong
uchar = c_ubyte

########################### LSB 64 BIT Structures ###########################

LSB_64_R_SYM = lambda i: i >> 32
LSB_64_R_TYPE = lambda i: i & 0xffffffff


class LSB_64_EHDR(LittleEndianStructure):
    _fields_ = [('e_ident', uchar * 16),
                ('e_type', Elf64_Half),
                ('e_machine', Elf64_Half),
                ('e_version', Elf64_Word),
                ('e_entry', Elf64_Addr),
                ('e_phoff', Elf64_Off),
                ('e_shoff', Elf64_Off),
                ('e_flags', Elf64_Word),
                ('e_ehsize', Elf64_Half),
                ('e_phentsize', Elf64_Half),
                ('e_phnum', Elf64_Half),
                ('e_shentsize', Elf64_Half),
                ('e_shnum', Elf64_Half),
                ('e_shstrndx', Elf64_Half)
                ]


class LSB_64_SHDR(LittleEndianStructure):
    _fields_ = [('sh_name', Elf64_Word),
                ('sh_type', Elf64_Word),
                ('sh_flags', Elf64_Xword),
                ('sh_addr', Elf64_Addr),
                ('sh_offset', Elf64_Off),
                ('sh_size', Elf64_Xword),
                ('sh_link', Elf64_Word),
                ('sh_info', Elf64_Word),
                ('sh_addralign', Elf64_Xword),
                ('sh_entsize', Elf64_Xword)
                ]


class LSB_64_SYM(LittleEndianStructure):
    _fields_ = [('st_name', Elf64_Word),
                ('st_info', uchar),
                ('st_other', uchar),
                ('st_shndx', Elf64_Half),
                ('st_value', Elf64_Addr),
                ('st_size', Elf64_Xword)
                ]


class LSB_64_REL(LittleEndianStructure):
    _fields_ = [('r_offset', Elf64_Addr),
                ('r_info', Elf64_Xword)]


class LSB_64_RELA(LittleEndianStructure):
    _fields_ = [('r_offset', Elf64_Addr),
                ('r_info', Elf64_Xword),
                ('r_addend', Elf64_Sxword)
                ]


class LSB_64_PHDR(LittleEndianStructure):
    _fields_ = [('p_type', Elf64_Word),
                ('p_flags', Elf64_Word),
                ('p_offset', Elf64_Off),
                ('p_vaddr', Elf64_Addr),
                ('p_paddr', Elf64_Addr),
                ('p_filesz', Elf64_Xword),
                ('p_memsz', Elf64_Xword),
                ('p_align', Elf64_Xword)
                ]

class LSB_64_DYN(LittleEndianStructure):
    _fields_ = [('d_tag', Elf64_Xword),
                ('d_un', Elf64_Xword)
                ]

class LSB_64():
    PHDR = LSB_64_PHDR
    EHDR = LSB_64_EHDR
    SHDR = LSB_64_SHDR
    REL = LSB_64_REL
    RELA = LSB_64_RELA
    SYM = LSB_64_SYM
    DYN = LSB_64_DYN
    R_SYM = staticmethod(LSB_64_R_SYM)
    R_TYPE = staticmethod(LSB_64_R_TYPE)

########################### MSB 64 BIT Structures ###########################

MSB_64_R_SYM = lambda i: i >> 32
MSB_64_R_TYPE = lambda i: i & 0xffffffff


class MSB_64_EHDR(BigEndianStructure):
    _fields_ = [('e_ident', uchar * 16),
                ('e_type', Elf64_Half),
                ('e_machine', Elf64_Half),
                ('e_version', Elf64_Word),
                ('e_entry', Elf64_Addr),
                ('e_phoff', Elf64_Off),
                ('e_shoff', Elf64_Off),
                ('e_flags', Elf64_Word),
                ('e_ehsize', Elf64_Half),
                ('e_phentsize', Elf64_Half),
                ('e_phnum', Elf64_Half),
                ('e_shentsize', Elf64_Half),
                ('e_shnum', Elf64_Half),
                ('e_shstrndx', Elf64_Half)
                ]


class MSB_64_SHDR(BigEndianStructure):
    _fields_ = [('sh_name', Elf64_Word),
                ('sh_type', Elf64_Word),
                ('sh_flags', Elf64_Xword),
                ('sh_addr', Elf64_Addr),
                ('sh_offset', Elf64_Off),
                ('sh_size', Elf64_Xword),
                ('sh_link', Elf64_Word),
                ('sh_info', Elf64_Word),
                ('sh_addralign', Elf64_Xword),
                ('sh_entsize', Elf64_Xword)
                ]


class MSB_64_SYM(BigEndianStructure):
    _fields_ = [('st_name', Elf64_Word),
                ('st_info', uchar),
                ('st_other', uchar),
                ('st_shndx', Elf64_Half),
                ('st_value', Elf64_Addr),
                ('st_size', Elf64_Xword)
                ]


class MSB_64_REL(BigEndianStructure):
    _fields_ = [('r_offset', Elf64_Addr),
                ('r_info', Elf64_Xword)]


class MSB_64_RELA(BigEndianStructure):
    _fields_ = [('r_offset', Elf64_Addr),
                ('r_info', Elf64_Xword),
                ('r_addend', Elf64_Sxword)
                ]


class MSB_64_PHDR(BigEndianStructure):
    _fields_ = [('p_type', Elf64_Word),
                ('p_flags', Elf64_Word),
                ('p_offset', Elf64_Off),
                ('p_vaddr', Elf64_Addr),
                ('p_paddr', Elf64_Addr),
                ('p_filesz', Elf64_Xword),
                ('p_memsz', Elf64_Xword),
                ('p_align', Elf64_Xword)
                ]

class MSB_64_DYN(BigEndianStructure):
    _fields_ = [('d_tag', Elf64_Xword),
                ('d_un', Elf64_Xword)
                ]

class MSB_64():
    PHDR = MSB_64_PHDR
    EHDR = MSB_64_EHDR
    SHDR = MSB_64_SHDR
    REL = MSB_64_REL
    RELA = MSB_64_RELA
    SYM = MSB_64_SYM
    DYN = MSB_64_DYN
    R_SYM = staticmethod(MSB_64_R_SYM)
    R_TYPE = staticmethod(MSB_64_R_TYPE)

################################ ELF File Implementation #########################################

class EhdrData(Container):
    """
    header = SectionHeader
    """

class ShdrData(Container):

    """
    header = SectionHeader
    name = string (section name)
    bytes = bytearray (section bytes)
    raw = c_ubyte_array

    .dynamic
    content = List of DYN entries

    .rel & .rela
    relocations = list of REL or RELA

    .dynsym & .symtab
    symbols = list of SYM entries
    """


class PhdrData(Container):

    """
    type = Programm Header Type
    header = ProgrammHeader
    bytes = bytearray (section bytes)
    raw = c_ubyte_array
    vaddr = virtual address (int)
    offset = offset
    """


class SymbolData(Container):

    """
    header = Symbol
    name = string
    type = int
    bind = bind
    """


class RelocationData(Container):

    """
    header = RelocationStruct
    symbol = SymbolData
    type = type of relocation
    """

class DynamicData(Container):
    """
    header = DYN
    tag = value of class DT

    """

##################### ELF Class ##############################

class ELF(Binary):

    def __init__(self, fileName, fileContent=None):
        super(ELF, self).__init__(fileName, fileContent)

        self.__classes = self._getSuitableClasses(self._bytes)
        if not self.__classes:
            raise BinaryError('Bad architecture')

        self.__elfHeader = self._parseElfHeader(self._bytes)
        self.__segments = self._parseSegments(self._bytes, self.elfHeader)
        self.__sections = self._parseSections(self._bytes, self.elfHeader)
        self._parseSymbols(self.sections)
        self._parseDynamic(self.sections)
        self._parseRelocations(self.sections)

    @property
    def _classes(self):
        return self.__classes


    @property
    def elfHeader(self):
        return self.__elfHeader


    @property
    def sections(self):
        return list(self.__sections)

    @property
    def segments(self):
        return list(self.__segments)

    @property
    def programHeaders(self):
        return list(self.__segments)

    @property
    def entryPoint(self):
        return self.elfHeader.header.e_entry

    @property
    def imageBase(self):
        return self.segments[0].header.p_vaddr - self.segments[0].header.p_offset if len(self.segments) > 0 else 0

    def _getSuitableClasses(self, data):
        """Returns the class which holds the suitable classes for the loaded file"""
        classes = None
        if data[EI.CLASS] == ELFCLASS.BITS_32:
            if data[EI.DATA] == ELFDATA.LSB:
                classes = LSB_32
            elif data[EI.DATA] == ELFDATA.MSB:
                classes = MSB_32

        elif data[EI.CLASS] == ELFCLASS.BITS_64:
            if data[EI.DATA] == ELFDATA.LSB:
                classes = LSB_64
            elif data[EI.DATA] == ELFDATA.MSB:
                classes = MSB_64

        return classes

    def _parseElfHeader(self, data):
        """Returns the elf header"""
        ehdr = self.__classes.EHDR.from_buffer(data)
        return EhdrData(header=ehdr)

    def _parseSegments(self, data, elfHeader):
        """Return a list of segments"""
        offset = elfHeader.header.e_phoff
        segments = []
        for i in range(elfHeader.header.e_phnum):
            phdr = self.__classes.PHDR.from_buffer(data, offset)
            segment_bytes = (c_ubyte * phdr.p_filesz).from_buffer(data, phdr.p_offset)

            phdrData = PhdrData(header=phdr, raw=segment_bytes, bytes=bytearray(segment_bytes), type=PT[phdr.p_type], vaddr=phdr.p_vaddr, offset=phdr.p_offset)
            segments.append(phdrData)

            offset += elfHeader.header.e_phentsize

        return segments

    def _parseSections(self, data, elfHeader):
        """Returns a list of sections"""
        offset = elfHeader.header.e_shoff
        shdrs = []
        for i in range(elfHeader.header.e_shnum):
            shdr = self.__classes.SHDR.from_buffer(data, offset)
            section_bytes = None
            ba_section_bytes = None
            if shdr.sh_type != SHT.NOBITS:
                section_bytes = (c_ubyte * shdr.sh_size).from_buffer(data, shdr.sh_offset)
                ba_section_bytes = bytearray(section_bytes)
            shdrs.append(ShdrData(name=None,header=shdr, raw=section_bytes, bytes=ba_section_bytes))
            offset += elfHeader.header.e_shentsize

        if elfHeader.header.e_shstrndx != SHN.UNDEF:
            strtab = shdrs[elfHeader.header.e_shstrndx]
            strtab_offset = strtab.header.sh_offset

            for section in shdrs:
                section.name = get_str(strtab.raw, section.header.sh_name)

        return shdrs

    def _parseSymbols(self, sections):
        """Sets a list of symbols in each DYNSYM and SYMTAB section"""
        for section in sections:
            strtab = sections[section.header.sh_link]
            if section.header.sh_type in (int(SHT.DYNSYM), int(SHT.SYMTAB)):
                section.symbols = self.__parseSymbolEntriesForSection(section, strtab)


    def __parseSymbolEntriesForSection(self, section, strtab):
        entries = []
        offset = 0
        bytes_p = cast(pointer(section.raw), c_void_p)
        sym_size = sizeof(self.__classes.SYM)

        for i in range(int(section.header.sh_size / sym_size)):
            entry = self.__classes.SYM.from_buffer(section.raw, offset)
            name = get_str(strtab.raw, entry.st_name)
            sym_data = SymbolData(header=entry, name=name, type=entry.st_info & 0xf, bind=entry.st_info >> 4)
            entries.append(sym_data)

            offset += sym_size

        return entries

    def _parseRelocations(self, sections):
        """Parses the relocations and add those to the section"""
        for section in sections:
            if section.header.sh_link != SHN.UNDEF and section.header.sh_type in (SHT.REL, SHT.RELA):
                symbols = sections[section.header.sh_link].symbols
                relocations = self.__parseRelocationEntries(section, symbols)
                section.relocations = relocations

    def __parseRelocationEntries(self, section, symbols):
        struct = self.__classes.REL if section.header.sh_type == SHT.REL else self.__classes.RELA
        struct_size = sizeof(struct)
        offset = 0
        entries = []

        for i in range(int(section.header.sh_size / struct_size)):
            entry = struct.from_buffer(section.raw, offset)
            sym = symbols[self.__classes.R_SYM(entry.r_info)]
            reloc_entry = RelocationData(header=entry, symbol=sym, type=self.__classes.R_TYPE(entry.r_info))
            entries.append(reloc_entry)
            offset += sizeof(struct)

        return entries

    def _parseDynamic(self, sections):

        dyn_size = sizeof(self._classes.DYN)

        for section in sections:
            offset = 0
            dyns = []
            if section.header.sh_type == SHT.DYNAMIC:
                for i in range(int(len(section.bytes) / dyn_size)):
                    dyn = self._classes.DYN.from_buffer(section.raw, offset)
                    dyns.append(DynamicData(header=dyn, tag=DT[dyn.d_tag]))
                    if dyn.d_tag == DT.NULL:
                        break
                    offset += dyn_size
                section.content = dyns
                self._parseDynamicTags(dyns, sections)

    def _parseDynamicTags(self, dyns, sections):

        for dyn in dyns:
            if dyn.header.d_tag == DT.NEEDED:
                self.__parseDynamicTagNeeded(dyn, dyns, sections)


    def __parseDynamicTagNeeded(self, dyn, dyns, sections):
        dyn_strtab = None
        for d in dyns:
            if d.header.d_tag == DT.STRTAB:
                dyn_strtab = d

        if not dyn_strtab:
            return

        for section in sections:
            if section.header.sh_addr == dyn_strtab.header.d_un:
                dyn.val = get_str(section.raw, dyn.header.d_un)
                break

    @classmethod
    def isSupportedContent(cls, fileContent):
        """Returns if the files are valid for this filetype"""
        return bytearray(fileContent)[:4] == b'\x7fELF'
