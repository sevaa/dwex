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

###################### PE General #################

class IMAGE_FILE_MACHINE(Enum):
    UKNOWN = 0
    AM33 = 0x1d3
    AMD64 = 0x8664
    ARM = 0x1c0
    ARMV = 0x1c4
    EBC = 0xebc
    I386 = 0x14c
    IA64 = 0x200
    M32R = 0x9041
    MIPS16 = 0x266
    MIPSFPU = 0x366
    MIPSFPU16 = 0x466
    POWERPC = 0x1f0
    POWERPCFP = 0x1f1
    THUMB = 0x1c2
    WCEMIPSV2 = 0x169
    ARM64 = 0xaa64    

class IMAGE_SCN(Enum):
    TYPE_NO_PAD = 0x00000008
    CNT_CODE = 0x00000020
    CNT_INITIALIZED_DATA = 0x00000040
    CNT_UNINITIALIZED_DATA = 0x00000080
    LNK_OTHER = 0x00000100
    LNK_INFO = 0x00000200
    LNK_REMOVE = 0x00000800
    LNK_COMDAT = 0x00001000
    GPREL = 0x00008000
    MEM_PURGEABLE = 0x00020000
    MEM_LOCKED = 0x00040000
    MEM_PRELOAD = 0x00080000
    ALIGN_1BYTES = 0x00100000
    ALIGN_2BYTES = 0x00200000
    ALIGN_4BYTES = 0x00300000
    ALIGN_8BYTES = 0x00400000
    ALIGN_16BYTES = 0x00500000
    ALIGN_32BYTES = 0x00600000
    ALIGN_64BYTES = 0x00700000
    ALIGN_128BYTES = 0x00800000
    ALIGN_256BYTES = 0x00900000
    ALIGN_512BYTES = 0x00A00000
    ALIGN_1024BYTES = 0x00B00000
    ALIGN_2048BYTES = 0x00C00000
    ALIGN_4096BYTES = 0x00D00000
    ALIGN_8192BYTES = 0x00E00000
    LNK_NRELOC_OVFL = 0x01000000
    MEM_WRITE = 0x80000000
    MEM_READ = 0x4000000



class ImageDllCharacteristics(Enum):
    DYNAMIC_BASE = 0x0040
    FORCE_INTEGRITY = 0x0080
    NX_COMPAT = 0x0100
    NO_ISOLATION = 0x0200
    NO_SEH = 0x0400
    NO_BIND = 0x0800
    APP_CONTAINER = 0x1000
    WDM_DRIVER = 0x2000
    CONTROL_FLOW_GUARD = 0x4000
    TERMINAL_SERVER_AWARE = 0x8000


class ImageDirectoryEntry(Enum):
    EXPORT = 0
    IMPORT = 1
    RESOURCE = 2
    EXCEPTION = 3
    SECURITY = 4
    BASERELOC = 5
    DEBUG = 6
    COPYRIGHT = 7
    GLOBALPTR = 8
    TLS = 9
    LOAD_CONFIG = 10
    BOUND_IMPORT = 11
    IAT = 12
    DELAY_IMPORT = 13
    COM_DESCRIPTOR = 14
    NUMBER_OF_DIRECTORY_ENTRIES = 16


class IMAGE_DOS_HEADER(Structure):
    _fields_ = [('e_magic', c_char * 2),
                ('e_cblp', c_ushort),
                ('e_cp', c_ushort),
                ('e_crlc', c_ushort),
                ('e_cparhdr', c_ushort),
                ('e_minalloc', c_ushort),
                ('e_maxalloc', c_ushort),
                ('e_ss', c_ushort),
                ('e_sp', c_ushort),
                ('e_csum', c_ushort),
                ('e_ip', c_ushort),
                ('e_cs', c_ushort),
                ('e_lfarlc', c_ushort),
                ('e_ovno', c_ushort),
                ('e_res', c_ushort * 4),
                ('e_oemid', c_ushort),
                ('e_oeminfo', c_ushort),
                ('e_res2', c_ushort * 10),
                ('e_lfanew', c_uint)]       # Offset zum PE-Header


class IMAGE_FILE_HEADER(Structure):
    _fields_ = [('Machine', c_ushort),
                ('NumberOfSections', c_ushort),
                ('TimeDateStamp', c_uint),
                ('PointerToSymbolTable', c_uint),
                ('NumberOfSymbols', c_uint),
                ('SizeOfOptionalHeader', c_ushort),
                ('Characteristics', c_ushort)
                ]


class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [('VirtualAddress', c_uint),
                ('Size', c_uint)]


class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [('Name', c_char * 8),
                ('PhysicalAddress_or_VirtualSize', c_uint),
                ('VirtualAddress', c_uint),
                ('SizeOfRawData', c_uint),
                ('PointerToRawData', c_uint),
                ('PointerToRelocations', c_uint),
                ('PointerToLinenumbers', c_uint),
                ('NumberOfRelocations', c_ushort),
                ('NumberOfLinenumbers', c_ushort),
                ('Characteristics', c_uint)]


class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [('Hint', c_ushort),
                ('Name', c_char)]


class IMAGE_THUNK_DATA(Union):
    _fields_ = [('ForwarderString', c_uint),
                ('Function', c_uint),
                ('Ordinal', c_uint),
                ('AddressOfData', c_uint)]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [('OriginalFirstThunk', c_uint),
                ('TimeDateStamp', c_uint),
                ('ForwarderChain', c_uint),
                ('Name', c_uint),
                ('FirstThunk', c_uint)]

class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [('Characteristics',c_uint),
                ('TimeDateStamp',c_uint),
                ('MajorVersion', c_ushort),
                ('MinorVersion', c_ushort),
                ('Name',c_uint),
                ('Base',c_uint),
                ('NumberOfFunctions',c_uint),
                ('NumberOfNames',c_uint),
                ('AddressOfFunctions',c_uint),
                ('AddressOfNames',c_uint),
                ('AddressOfNameOrdinals',c_uint)
                ]

class GUARD_CFF_ENTRY(Structure):
    _fields_ = [('rva',c_uint),
                ('flag', c_byte)]

##################### PE32 ########################

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_byte),
                ('MinorLinkerVersion', c_byte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('BaseOfData', c_uint),
                ('ImageBase', c_uint),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_uint),
                ('SizeOfStackCommit', c_uint),
                ('SizeOfHeapReserve', c_uint),
                ('SizeOfHeapCommit', c_uint),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)]


class PE32_IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', c_char * 4),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER)]

class PE32(object):
    IMAGE_NT_HEADERS = PE32_IMAGE_NT_HEADERS


class IMAGE_LOAD_CONFIG_DIRECTORY32(Structure):
    _fields_ = [('Size', c_uint),
                ('TimeDateStamp', c_uint),
                ('MajorVersion', c_ushort),
                ('MinorVersion', c_ushort),
                ('GlobalFlagsClear', c_uint),
                ('GlobalFlagsSet', c_uint),
                ('CriticalSectionDefaultTimeout', c_uint),
                ('DeCommitFreeBLockThreshold', c_uint),
                ('DeCommitTotalFreeThreshold', c_uint),
                ('LockPrefixTable', c_uint),
                ('MaximumAllocationSize', c_uint),
                ('VirtualMemoryThreshold', c_uint),
                ('ProcessHeapFlags', c_uint),
                ('ProcessAffinityMask', c_uint),
                ('CSDVersion', c_ushort),
                ('Reserved1', c_ushort),
                ('EditList', c_uint),
                ('SecurityCookie', c_uint),
                ('SEHandlerTable', c_uint),
                ('SEHandlerCount', c_uint),
                ('GuardCFCheckFunctionPointer', c_uint),
                ('Reserved2', c_uint),
                ('GuardCFFunctionTable', c_uint),
                ('GuardCFFunctionCount', c_uint),
                ('GuardFlags', c_uint)]


######################### PE64 ########################

class IMAGE_OPTIONAL_HEADER_PE32_PLUS(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_ubyte),
                ('MinorLinkerVersion', c_ubyte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('ImageBase', c_ulonglong),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_ulonglong),
                ('SizeOfStackCommit', c_ulonglong),
                ('SizeOfHeapReserve', c_ulonglong),
                ('SizeOfHeapCommit', c_ulonglong),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)]


class PE64_IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', c_char * 4),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER_PE32_PLUS)]

class PE64(object):
    IMAGE_NT_HEADERS = PE64_IMAGE_NT_HEADERS


class IMAGE_LOAD_CONFIG_DIRECTORY64(Structure):
    _fields_ = [('Size', c_uint),
                ('TimeDateStamp', c_uint),
                ('MajorVersion', c_ushort),
                ('MinorVersion', c_ushort),
                ('GlobalFlagsClear', c_uint),
                ('GlobalFlagsSet', c_uint),
                ('CriticalSectionDefaultTimeout', c_uint),
                ('DeCommitFreeBLockThreshold', c_ulonglong),
                ('DeCommitTotalFreeThreshold', c_ulonglong),
                ('LockPrefixTable', c_ulonglong),
                ('MaximumAllocationSize', c_ulonglong),
                ('VirtualMemoryThreshold', c_ulonglong),
                ('ProcessAffinityMask', c_ulonglong),
                ('ProcessHeapFlags', c_uint),
                ('CSDVersion', c_ushort),
                ('Reserved1', c_ushort),
                ('EditList', c_ulonglong),
                ('SecurityCookie', c_ulonglong),
                ('SEHandlerTable', c_ulonglong),
                ('SEHandlerCount', c_ulonglong),
                ('GuardCFCheckFunctionPointer', c_ulonglong),
                ('Reserved2', c_ulonglong),
                ('GuardCFFunctionTable', c_ulonglong),
                ('GuardCFFunctionCount', c_ulonglong),
                ('GuardFlags', c_uint)]

##################### Container ###################


def to_offset(addr, section):
    return addr - section.header.VirtualAddress

def to_raw_address(addr, section):
        """Converts the addr from a rva to a pointer to raw data in the file"""
        return addr - section.header.VirtualAddress + section.header.PointerToRawData

class ImageDosHeaderData(Container):
    """
    header = IMAGE_DOS_HEADER
    """

class ImageNtHeaderData(Container):
    """
    header = IMAGE_NT_HEADERS
    """

class SectionData(Container):
    """
    header = IMAGE_SECTION_HEADER
    name = name of the section (str)
    bytes = bytes of section (bytearray)
    raw = bytes of section (c_ubyte_array)
    """

class DataDirectoryData(Container):
    """
    header = IMAGE_DATA_DIRECTORY
    """

class ImportDescriptorData(Container):
    """
    header = IMAGE_IMPORT_DESCRIPTOR
    dllName = name of dll (str)
    importNameTable = list of IMAGE_THUNK_DATA
    importAddressTable = list of IMAGE_THUNK_DATA
    """

class ImportByNameData(Container):
    """
    header = IMAGE_IMPORT_BY_NAME
    name = name of function (str)
    """


class ThunkData(Container):
    """
    header = IMAGE_THUNK_DATA
    rva = relative virtual address of thunk
    ordinal = None | Ordinal
    importByName = None| ImportByNameData
    """

class ExportDirectoryData(Container):
    """
    header = IMAGE_EXPORT_DIRECTORY
    name = name of dll (str)
    functions = list of FunctionData
    """

class LoadConfigData(Container):
    """"
    header = IMAGE_LOAD_CONFIG_DIRECTORY32/IMAGE_LOAD_CONFIG_DIRECTORY64
    cfGuardedFunctions = list of relative virtual addresses (RVA) of cfg allowed call/jmp targets. Empty if CFG not supported
    """

class FunctionData(Container):
    """
    name = name of the function (str)
    ordinal = ordinal (int)
    rva = relative virtual address of function (int)
    """

def checkOffset(offset, section):
    size = len(section.raw)
    if offset < 0 or offset > size:
        raise BinaryError('Invalid offset: {} (data size: {})'.format(offset, size))

class PE(Binary):

    def __init__(self, fileName, fileContent=None, parse_header_only=False):
        super(PE, self).__init__(fileName, fileContent)



        self.__imageDosHeader = self._parseImageDosHeader(self._bytes)
        self.__classes = self._getSuitableClasses(self._bytes, self.imageDosHeader)

        if not self.__classes:
            raise BinaryError('Bad architecture')

        self.__imageNtHeaders = self._parseImageNtHeaders(self._bytes, self.imageDosHeader)
        self.__sections = self._parseSections(self._bytes, self.imageDosHeader, self.imageNtHeaders, parse_header_only=parse_header_only)

        if parse_header_only:
            self.__dataDirectory = None
        else:
            self.__dataDirectory = self._parseDataDirectory(self._bytes, self.sections, self.imageNtHeaders)


    @property
    def _classes(self):
        return self.__classes

    @property
    def imageDosHeader(self):
        return self.__imageDosHeader

    @property
    def imageNtHeaders(self):
        return self.__imageNtHeaders

    @property
    def sections(self):
        return self.__sections

    @property
    def dataDirectory(self):
        return self.__dataDirectory


    @property
    def entryPoint(self):
        return self.imageNtHeaders.header.OptionalHeader.ImageBase + self.imageNtHeaders.header.OptionalHeader.AddressOfEntryPoint

    @property
    def imageBase(self):
        return self.imageNtHeaders.header.OptionalHeader.ImageBase

    @property
    def type(self):
        return 'PE'

    def _getSuitableClasses(self, data, imageDosHeader):
        """Returns the class which holds the suitable classes for the loaded file"""
        classes = None
        machine = IMAGE_FILE_MACHINE[c_ushort.from_buffer(data,imageDosHeader.header.e_lfanew+4).value]

        if machine == IMAGE_FILE_MACHINE.I386:
            classes = PE32
        elif machine == IMAGE_FILE_MACHINE.AMD64:
            classes = PE64

        return classes

    def _parseImageDosHeader(self, data):
        """Returns the ImageDosHeader"""
        ioh = IMAGE_DOS_HEADER.from_buffer(data)
        if ioh.e_magic != b'MZ':
            raise BinaryError('No valid PE/COFF file')

        return ImageDosHeaderData(header=ioh)

    def _parseImageNtHeaders(self, data, imageDosHeader):
        """Returns the ImageNtHeaders"""
        inth = self._classes.IMAGE_NT_HEADERS.from_buffer(data, imageDosHeader.header.e_lfanew)

        if inth.Signature != b'PE':
            raise BinaryError('No valid PE/COFF file')

        return ImageNtHeaderData(header=inth)

    def _parseSections(self, data, imageDosHeader, imageNtHeaders, parse_header_only=False):
        """Parses the sections in the memory and returns a list of them"""
        sections = []

        optional_header_offset = imageDosHeader.header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
        offset = optional_header_offset + imageNtHeaders.header.FileHeader.SizeOfOptionalHeader  # start reading behind the dos- and ntheaders

        image_section_header_size = sizeof(IMAGE_SECTION_HEADER)
        IMAGE_SIZEOF_SYMBOL = 18
        strtable_offset = imageNtHeaders.header.FileHeader.PointerToSymbolTable + IMAGE_SIZEOF_SYMBOL * imageNtHeaders.header.FileHeader.NumberOfSymbols

        for sectionNo in range(imageNtHeaders.header.FileHeader.NumberOfSections):
            ishdr = IMAGE_SECTION_HEADER.from_buffer(data, offset)

            if parse_header_only:
                raw = None
                bytes_ = bytearray()
            else:
                size = ishdr.SizeOfRawData
                raw = (c_ubyte * size).from_buffer(data, ishdr.PointerToRawData)
                bytes_ = bytearray(raw)

            secname = ishdr.Name.decode('ASCII', errors='ignore')
            if secname.startswith('/'):
                name_offset = int(secname[1:]) + strtable_offset
                s = bytearray()
                while self._bytes[name_offset] != 0:
                    s.append(self._bytes[name_offset])
                    name_offset += 1
                secname = bytes(s).decode('ASCII', errors='ignore')

            sections.append(SectionData(header=ishdr, name=secname, bytes=bytes_, raw=raw))

            offset += image_section_header_size

        return sections

    def _getSectionForDataDirectoryEntry(self, data_directory_entry, sections):
        """Returns the section which contains the data of DataDirectory"""
        for section in sections:
            if data_directory_entry.VirtualAddress >= section.header.VirtualAddress and \
            data_directory_entry.VirtualAddress < section.header.VirtualAddress + section.header.SizeOfRawData :

                return section

    def _parseDataDirectory(self, data, sections, imageNtHeaders):
        """Parses the entries of the DataDirectory and returns a list of the content"""
        data_directory_data_list = [None for i in range(15)]

        # parse DataDirectory[Export]
        export_data_directory = imageNtHeaders.header.OptionalHeader.DataDirectory[ImageDirectoryEntry.EXPORT]
        export_section = self._getSectionForDataDirectoryEntry(export_data_directory, sections)
        export_data_directory_data = self._parseDataDirectoryExport(data, export_data_directory, export_section)
        data_directory_data_list[ImageDirectoryEntry.EXPORT] = export_data_directory_data

        # parse DataDirectory[Import]
        import_data_directory = imageNtHeaders.header.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMPORT]
        import_section = self._getSectionForDataDirectoryEntry(import_data_directory, sections)
        import_data_directory_data = self._parseDataDirectoryImport(import_data_directory, import_section)
        data_directory_data_list[ImageDirectoryEntry.IMPORT] = import_data_directory_data

        # parse DataDirectory[LOAD_CONFIG]
        loadconfig_data_directory = imageNtHeaders.header.OptionalHeader.DataDirectory[ImageDirectoryEntry.LOAD_CONFIG]
        loadconfig_section = self._getSectionForDataDirectoryEntry(loadconfig_data_directory, sections)
        loadconfig_data = self._parseLoadConfig(loadconfig_data_directory, loadconfig_section)
        data_directory_data_list[ImageDirectoryEntry.LOAD_CONFIG] = loadconfig_data

        return data_directory_data_list

    def _parseDataDirectoryExport(self, data, dataDirectoryEntry, exportSection):
        """Parses the EmportDataDirectory and returns an instance of ExportDirectoryData"""
        if not exportSection:
            return
        functions = []
        export_directory = IMAGE_EXPORT_DIRECTORY.from_buffer(exportSection.raw, to_offset(dataDirectoryEntry.VirtualAddress, exportSection))
        offset = to_offset(export_directory.Name, exportSection)

        checkOffset(offset, exportSection)
        name = get_str(exportSection.raw, offset)

        offsetOfNames = to_offset(export_directory.AddressOfNames, exportSection)
        offsetOfAddress = to_offset(export_directory.AddressOfFunctions, exportSection)
        offsetOfNameOrdinals = to_offset(export_directory.AddressOfNameOrdinals, exportSection)
        for i in range(export_directory.NumberOfNames):
            name_address = c_uint.from_buffer(exportSection.raw, offsetOfNames).value
            name_offset = to_offset(name_address, exportSection)

            checkOffset(name_offset, exportSection)
            func_name = get_str(exportSection.raw, name_offset)
            ordinal = c_ushort.from_buffer(exportSection.raw, offsetOfNameOrdinals).value
            func_addr = c_uint.from_buffer(exportSection.raw, offsetOfAddress).value

            offsetOfNames += 4
            offsetOfAddress += 4
            offsetOfNameOrdinals += 2
            functions.append(FunctionData(name=func_name, rva=func_addr, ordinal=ordinal))

        return ExportDirectoryData(header=export_directory, name=name, functions=functions)

    def _parseDataDirectoryImport(self, dataDirectoryEntry, importSection):
        """Parses the ImportDataDirectory and returns a list of ImportDescriptorData"""
        if not importSection:
            return


        raw_bytes = (c_ubyte * dataDirectoryEntry.Size).from_buffer(importSection.raw, to_offset(dataDirectoryEntry.VirtualAddress, importSection))
        offset = 0
        import_descriptors = []
        while True:
            import_descriptor = IMAGE_IMPORT_DESCRIPTOR.from_buffer(raw_bytes, offset)


            if import_descriptor.OriginalFirstThunk == 0:
                break
            else:
                nameOffset = to_offset(import_descriptor.Name, importSection)

                checkOffset(nameOffset, importSection)
                dllName = get_str(importSection.raw, nameOffset)

                import_name_table =  self.__parseThunks(import_descriptor.OriginalFirstThunk, importSection)
                import_address_table =  self.__parseThunks(import_descriptor.FirstThunk, importSection)

                import_descriptors.append(ImportDescriptorData(header=import_descriptor, dllName=dllName, importNameTable=import_name_table, importAddressTable=import_address_table))
            offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)
        return import_descriptors

    def _getSectionByRVA(self, va):
        for section in self.sections:
            address = section.header.VirtualAddress
            SizeOfRawData = section.header.SizeOfRawData
            if  address <= va and va < (address + SizeOfRawData):
                return section

        return

    def _parseLoadConfig(self, loadConfigEntry, loadconfigSection):
        if not loadconfigSection:
            return

        if self._classes == PE64:
            load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORY64.from_buffer(
                loadconfigSection.raw, to_offset(loadConfigEntry.VirtualAddress, loadconfigSection))

            pass

        elif self._classes == PE32:
            load_config_directory = IMAGE_LOAD_CONFIG_DIRECTORY32.from_buffer(
                loadconfigSection.raw, to_offset(loadConfigEntry.VirtualAddress, loadconfigSection))

            pass
        else:
            pass

        guardCFTableRVA = load_config_directory.GuardCFFunctionTable - self.imageBase
        section = self._getSectionByRVA(guardCFTableRVA)
        CfGuardedFunctions = set()
        if section:
            sectionOffset = guardCFTableRVA - section.header.VirtualAddress

            # loop through the ControlFlow Guard Function table
            for i in range(0, load_config_directory.GuardCFFunctionCount):
                cffEntry = GUARD_CFF_ENTRY.from_buffer(section.raw, sectionOffset)
                CfGuardedFunctions.add(cffEntry.rva)
                sectionOffset += 5

        return LoadConfigData(header=load_config_directory, cfGuardedFunctions=CfGuardedFunctions )

    def __parseThunks(self, thunkRVA, importSection):
        """Parses the thunks and returns a list"""
        offset = to_offset(thunkRVA, importSection)
        table_offset = 0
        thunks = []
        while True:
            thunk = IMAGE_THUNK_DATA.from_buffer(importSection.raw, offset)
            offset += sizeof(IMAGE_THUNK_DATA)
            if thunk.Ordinal == 0:
                break
            thunkData = ThunkData(header=thunk, rva=table_offset+thunkRVA,ordinal=None, importByName=None)
            if to_offset(thunk.AddressOfData, importSection) > 0 and to_offset(thunk.AddressOfData, importSection) < len(self._bytes):
                self.__parseThunkData(thunkData, importSection)
            thunks.append(thunkData)
            table_offset += 4
        return thunks

    def __parseThunkData(self, thunk,importSection):
        """Parses the data of a thunk and sets the data"""
        offset = to_offset(thunk.header.AddressOfData, importSection)
        if 0xf0000000 & thunk.header.AddressOfData == 0x80000000:
            thunk.ordinal = thunk.header.AddressOfData & 0x0fffffff
        else:
            ibn = IMAGE_IMPORT_BY_NAME.from_buffer(importSection.raw, offset)

            checkOffset(offset+2, importSection)
            name = get_str(importSection.raw, offset+2)
            thunk.importByName = ImportByNameData(header=ibn, hint=ibn.Hint, name=name)

    @classmethod
    def isSupportedContent(cls, fileContent):
        """Returns if the files are valid for this filetype"""
        return bytearray(fileContent)[:2] == b'MZ'
