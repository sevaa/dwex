from collections import namedtuple
import io, os
from os import path, listdir
from elftools.dwarf.dwarfinfo import DWARFInfo, DebugSectionDescriptor, DwarfConfig
# This doesn't depend on Qt
# The dependency on filebytes only lives here
# Format codes: 0 = ELF, 1 = MACHO, 2 = PE, 3 - WASM, 4 - ELF inside A, 5 - arch specific MachO inside A

class FormatError(Exception):
    def __init__(self, s):
        Exception.__init__(self, s)

def read_pe(filename):
    from filebytes.pe import PE, IMAGE_FILE_MACHINE
    import struct, zlib

    pefile = PE(filename)

    # Section's real size might be padded - see https://github.com/sashs/filebytes/issues/28
    sections = [(section.name if section.name[1] != 'z' else '.' + section.name[2:],
        section.name[1] == 'z',
        section,
        section.header.PhysicalAddress_or_VirtualSize,
        section.header.SizeOfRawData)
        for section in pefile.sections
        if section.name.startswith('.debug') or section.name.startswith('.zdebug')]
    
    def read_section(name, is_compressed, section, virtual_size, raw_size):
        data = section.bytes
        size = raw_size if virtual_size == 0 else min((raw_size, virtual_size))
        if is_compressed:
            if size < 12:
                raise FormatError("Compressesed section %s is unexpectedly short." % (name,))
            if data[0:4] != b'ZLIB':
                raise FormatError("Unsupported format in compressesed section %s, ZLIB is expected." % (name,))
            (size,) = struct.unpack_from('>Q', data, offset=4)
            data = zlib.decompress(data[12:])
            if len(data) != size:
                raise FormatError("Wrong uncompressed size in compressesed section %s: expected %d, got %d." % (name, size, len(data)))
        return DebugSectionDescriptor(io.BytesIO(data), name, None, size, 0)

    data = {sec[0]: read_section(*sec) for sec in sections}

    if not '.debug_info' in data:
        return None

    machine = pefile.imageNtHeaders.header.FileHeader.Machine
    is64 = machine in (IMAGE_FILE_MACHINE.AMD64, IMAGE_FILE_MACHINE.ARM64, IMAGE_FILE_MACHINE.IA64) # There are also some exotic architectures...
    di = DWARFInfo(
        config = DwarfConfig(
            little_endian = True,
            default_address_size = 8 if is64 else 4,
            machine_arch = IMAGE_FILE_MACHINE[machine].name
        ),
        debug_info_sec = data['.debug_info'],
        debug_aranges_sec = data.get('.debug_aranges'),
        debug_abbrev_sec = data.get('.debug_abbrev'),
        debug_frame_sec = data.get('.debug_frame'),
        eh_frame_sec = None, # Unwind/exceptino info is stored in PE elsewhere
        debug_str_sec = data.get('.debug_str'),
        debug_loc_sec = data.get('.debug_loc'),
        debug_ranges_sec = data.get('.debug_ranges'),
        debug_line_sec = data.get('.debug_line'),
        debug_pubtypes_sec = data.get('.debug_pubtypes'),
        debug_pubnames_sec = data.get('.debug_pubnames'),
        debug_addr_sec = data.get('.debug_addr'),
        debug_str_offsets_sec = data.get('.debug_str_offsets'),
        debug_line_str_sec = data.get('.debug_line_str'),
        debug_loclists_sec = data.get('.debug_loclists'),
        debug_rnglists_sec = data.get('.debug_rnglists'),
        debug_sup_sec = data.get('.debug_sup'),
        gnu_debugaltlink_sec = data.get('.gnu_debugaltlink')
    )
    di._format = 2
    di._arch_code = machine
    di._start_address = pefile.imageNtHeaders.header.OptionalHeader.ImageBase
    di._frames = None
    return di

########################################################################
######################### MachO
########################################################################

# Arch + flavor where flavor matters
def make_macho_arch_name(macho):
    from filebytes.mach_o import CpuType, CpuSubTypeARM, CpuSubTypeARM64
    h = macho.machHeader.header
    c = h.cputype
    st = h.cpusubtype
    flavor = ''
    if st != 0:
        if c == CpuType.ARM:
            flavor = CpuSubTypeARM[st].name
        elif c == CpuType.ARM64:
            flavor = CpuSubTypeARM64[st].name
    return CpuType[c].name + flavor
        
# For debugging purposes only - dump individual debug related sections in a Mach-O file/slice as files
def macho_save_sections(filename, macho):
    from filebytes.mach_o import LC
    arch = make_macho_arch_name(macho)
    for cmd in macho.loadCommands:
        if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64):
            for section in cmd.sections:
                if section.name.startswith('__debug'):
                    sec_file = ".".join((filename, arch, section.name))
                    if not path.exists(sec_file):
                        with open(sec_file, 'wb') as f:
                            f.write(section.bytes)


# resolve_arch takes a list of architecture descriptions, and returns
# the desired index, or None if the user has cancelled
def read_macho(filename, resolve_arch, friendly_filename):
    from filebytes.mach_o import MachO
    fat_arch = None
    macho = MachO(filename)
    if macho.isFat:
        slices = [make_macho_arch_name(slice) for slice in macho.fatArches]
        arch_no = resolve_arch(slices, 'Mach-O Fat Binary', 'Choose an architecture:')
        if arch_no is None: # User cancellation
            return False
        fat_arch = slices[arch_no]
        macho = macho.fatArches[arch_no]

    return get_macho_dwarf(macho, fat_arch)

def get_macho_dwarf(macho, fat_arch):
    from filebytes.mach_o import CpuType, TypeFlags, LC
    # We proceed with macho being a arch-specific file, or a slice within a fat binary
    sections = {
        section.name: section.bytes
        for cmd in macho.loadCommands
        if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64)
        for section in cmd.sections
        if (section.name.startswith('__debug') or section.name in ('__eh_frame', '__unwind_info')) and section.header.offset > 0
    }

    if not '__debug_info' in sections:
        return None
    
    data = {
        name: DebugSectionDescriptor(io.BytesIO(contents), name, None, len(contents), 0)
        for (name, contents)
        in sections.items()
    }
    # '__eh_frame', '__unwind_info' are not in dSYM bundles

    #macho_save_sections(friendly_filename, macho)

    cpu = macho.machHeader.header.cputype
    di = DWARFInfo(
        config = DwarfConfig(
            little_endian=True,
            default_address_size = 8 if (cpu & TypeFlags.ABI64) != 0 else 4,
            machine_arch = make_macho_arch_name(macho)
        ),
        debug_info_sec = data['__debug_info'],
        debug_aranges_sec = data.get('__debug_aranges'),
        debug_abbrev_sec = data['__debug_abbrev'],
        debug_frame_sec = data.get('__debug_frame'),
        eh_frame_sec = data.get('__eh_frame'), # __unwind_info separately, not a part of DWARF proper
        debug_str_sec = data['__debug_str'],
        debug_loc_sec = data.get('__debug_loc'),
        debug_ranges_sec = data.get('__debug_ranges'),
        debug_line_sec = data.get('__debug_line'),
        debug_pubtypes_sec = data.get('__debug_pubtypes'), #__debug_gnu_pubn?
        debug_pubnames_sec = data.get('__debug_pubtypes'), #__debug_gnu_pubt?
        debug_addr_sec = data.get('__debug_addr'),
        debug_str_offsets_sec = data.get('__debug_str_offsets'),
        debug_line_str_sec = data.get('__debug_line_str'),
        debug_loclists_sec = data.get('__debug_loclists'),
        debug_rnglists_sec = data.get('__debug_rnglists'),
        debug_sup_sec = data.get('__debug_sup'),
        gnu_debugaltlink_sec = data.get('__gnu_debugaltlink')
    )
    di._unwind_sec = sections.get('__unwind_info') # VERY unlikely to be None
    di._format = 1
    di._arch_code = (macho.machHeader.header.cputype, macho.machHeader.header.cpusubtype)
    di._fat_arch = fat_arch
    uuid = next(cmd for cmd in macho.loadCommands if cmd.header.cmd == LC.UUID).uuid
    di._uuid = uuid
    text_cmd = next((cmd for cmd in macho.loadCommands if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64) and cmd.name == "__TEXT"), False)
    di._start_address = text_cmd.header.vmaddr if text_cmd else 0
    di._frames = None
    di._has_exec = False
    return di

def load_companion_executable(filename, di):
    from filebytes.mach_o import MachO, CpuType, TypeFlags, LC, BinaryError
    if path.isdir(filename):
        binary = binary_from_bundle(filename)
        if not binary:
            raise FormatError("The specified bundle does not contain a Mach-O binary, or it could not be found. Try locating the binary manually.")
    else:
        binary = filename
    
    try:
        macho = MachO(binary)
    except BinaryError:
        raise FormatError("This file is not a valid Mach-O binary.")
    
    if macho.isFat:
        macho = next((slice for slice in macho.fatArches if (slice.machHeader.header.cputype, slice.machHeader.header.cpusubtype) == di._arch_code), None)
        if macho is None:
            arch = di._fat_arch
            raise FormatError(f"This binary does not contain a slice for {arch}.")
    elif (macho.machHeader.header.cputype, macho.machHeader.header.cpusubtype) != di._arch_code:
        raise FormatError(f"The architecture of this binary does not match that of the curernt DWARF, which is {arch}.")

    uuid = next(cmd for cmd in macho.loadCommands if cmd.header.cmd == LC.UUID).uuid
    if uuid != di._uuid:
        raise FormatError(f"This binary is from a different build than the current DWARF - the UUIDs do not match.")
    
    # Match on arch and UUID
    sections = {
        section.name: section
        for cmd in macho.loadCommands
        if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64)
        for section in cmd.sections
        if section.header.offset > 0
    }

    di._unwind_sec = sections.get('__unwind_info').bytes
    di._text_sec = sections.get('__text').bytes

    #with open(binary+".__text", "wb") as tsf:
    #    tsf.write(di._text_sec)

    eh = sections.get('__eh_frame', None)
    if eh:
        di.eh_frame_sec = DebugSectionDescriptor(io.BytesIO(eh.bytes), eh.name, None, len(eh.bytes), 0)
    di._text_section_start = sections.get('__text').header.addr
    di._has_exec = True

def binary_from_bundle(filename):
    # Is it a dSYM bundle?
    nameparts = path.basename(filename).split('.') 
    if nameparts[-1] == 'dSYM' and path.exists(path.join(filename, 'Contents', 'Resources', 'DWARF')):
        files = listdir(path.join(filename, 'Contents', 'Resources', 'DWARF'))
        if len(files) > 0:
            # When are there multiple DWARF files in a dSYM bundle?
            # TODO: let the user choose?
            dsym_file_path = path.join(filename, 'Contents', 'Resources', 'DWARF', files[0])
            return dsym_file_path
    # Is it an app bundle? appname.app
    if len(nameparts) > 1 and nameparts[-1] in ('app', 'framework'):
        app_file = path.join(filename, '.'.join(nameparts[0:-1]))
        if path.exists(app_file):
            return app_file

        # Any other bundle formats we should be aware of?
    return None

########################################################################
######################### WASM
########################################################################

_WASM_section_header = False

def read_wasm(file):
    global _WASM_section_header
    from elftools.common.construct_utils import ULEB128, StreamOffset
    from elftools.construct import ULInt8, ULInt32, Struct, If, PascalString, Value
    if not _WASM_section_header:
        _WASM_section_header = Struct('WASMSectionHeader',
            ULInt8('id'),
            ULEB128('section_length'),
            StreamOffset('off1'),
            # Subheader on custom (id 0) sections - ULEB128 length prefixed name
            If(lambda ctx: ctx.id == 0, PascalString('name', length_field = ULEB128('length'), encoding='UTF-8')),
            StreamOffset('off2'),
            # This is effective content length - for custom sections, section size minus the name subheader
            Value('length', lambda ctxt: ctxt.section_length - ctxt.off2 + ctxt.off1)
        )
    
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    # Signature already checked, move on to file version
    file.seek(4, os.SEEK_SET)
    ver = ULInt32('').parse_stream(file)
    if ver != 1:
        raise FormatError("WASM binary format version %d is not supported." % ver)
    
    data = dict()
    dwarf_url = None
    while file.tell() < file_size:
        sh = _WASM_section_header.parse_stream(file)
        if sh.id == 0 and sh.name.startswith(".debug"):
            content = file.read(sh.length)
            data[sh.name] = DebugSectionDescriptor(io.BytesIO(content), sh.name, None, sh.length, 0)
        elif sh.id == 0 and sh.name == 'external_debug_info':
            dwarf_url = file.read(sh.length).decode('UTF-8')
        else: # Skip this section
            file.seek(sh.length, os.SEEK_CUR)

    if dwarf_url:
        raise FormatError("The debug information for this WASM file is at %s." % dwarf_url)

    # TODO: relocations, start address

    di = DWARFInfo(
        config = DwarfConfig(
            little_endian=True,
            default_address_size = 4, # Is it variable???
            machine_arch = 'WASM'
        ),
        debug_info_sec = data['.debug_info'],
        debug_aranges_sec = data.get('.debug_aranges'),
        debug_abbrev_sec = data['.debug_abbrev'],
        debug_frame_sec = data.get('.debug_frame'),
        eh_frame_sec = None, # In WASM??
        debug_str_sec = data['.debug_str'],
        debug_loc_sec = data.get('.debug_loc'),
        debug_ranges_sec = data.get('.debug_ranges'),
        debug_line_sec = data.get('.debug_line'),
        debug_pubtypes_sec = data.get('.debug_pubtypes'),
        debug_pubnames_sec = data.get('.debug_pubtypes'),
        debug_addr_sec = data.get('.debug_addr'),
        debug_str_offsets_sec = data.get('.debug_str_offsets'),
        debug_line_str_sec = data.get('.debug_line_str'),
        debug_loclists_sec = data.get('.debug_loclists'),
        debug_rnglists_sec = data.get('.debug_rnglists'),
        debug_sup_sec = None,
        gnu_debugaltlink_sec = None
    )
    di._format = 3
    di._arch_code = None #N/A
    di._start_address = 0
    di._frames = None
    return di

# Filename is only needed for supplemental DWARF resolution
def read_elf(file, filename):
    from elftools.elf.elffile import ELFFile
    file.seek(0)
    # TODO: interactive supplemental DWARF resolver here...
    elffile = ELFFile(file, lambda s: open(path.join(path.dirname(filename), s), 'rb'))

    # Retrieve the preferred loading address
    load_segment = next((seg for seg in elffile.iter_segments() if seg.header.p_type == 'PT_LOAD'), None)
    start_address = load_segment.header.p_vaddr if load_segment else 0
    di = None
    if elffile.has_dwarf_info():
        di = elffile.get_dwarf_info(elffile.header.e_type != 'ET_REL')
    elif elffile.get_section_by_name(".debug"):
        from .dwarfone import parse_dwarf1
        di = parse_dwarf1(elffile)

    if di:
        di._format = 0
        di._start_address = start_address
        di._arch_code = elffile.header.e_machine
        di._frames = None
    return di

_ar_file_header = namedtuple('ARHeader', ('header_offset', 'data_offset',
                                          'name',
                                          # Don't care for the metadata
                                          #'last_mod_date', 'user_id', 'group_id', 'mode',
                                          'size'))

# resolve_slice takes a list of files in the archive, and returns
# the desired index, or None if the user has cancelled
def read_staticlib(file, resolve_slice):
    from io import BytesIO
    long_names = False
    def read_header():
        header_offset = file.tell()
        b = file.read(60)
        data_size = int(b[48:58])
        name = b[0:16].rstrip()
        # Resolve BSD style long names
        if name.startswith(b'#1/') and len(name) > 3:
            name_len = int(name[3:])
            name = file.read(name_len).rstrip(b'\0')
            data_size -= name_len
        # Resolve GNU style long file names
        elif name.startswith(b'/') and len(name) > 1 and ord(b'0') <= name[1] <= ord(b'9'):
            if not long_names:
                FormatError("Long file name in a static library, but no long name section was found.")
            str_offset = int(name[1:])
            end_pos = long_names.find(b'\n', str_offset)
            name = long_names[str_offset:end_pos] if end_pos >= 0 else long_names[str_offset:]
        data_offset = file.tell()
        return _ar_file_header(header_offset, data_offset, name,
                               #int(b[16:28]), int(b[28:34]),
                               #int(b[34:40]), int(b[40:48], 8),
                               data_size)
    
    # Not used. Just in case. GNU symtab only.
    def read_symtab(size, is64):
        ilen = 8 if is64 else 4
        length = int.from_bytes(file.read(ilen), 'big')
        d = file.read(length * ilen)
        offsets = [int.from_bytes(d[i*ilen:(i+1)*ilen], 'big') for i in range(length)]
        d = file.read(size - (length+1)*ilen)
        symbols = d.split(b'\0')[:-1]
        return zip(offsets, symbols)
    
    def skip_content(header):
        file.seek(((header.size + 1) // 2) * 2, os.SEEK_CUR)

    ############################
    # read_staticlib starts here
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(8) # Past the magic signature

    # First section most likely a symtab - skip
    header = read_header() 
    if header.name == b'/' or header.name == b'/SYM64/' or header.name == b'__.SYMDEF':
        skip_content(header)
        # read_symtab(header.size, header.name == b'/SYM64/')
        # if header.size % 2 == 1:
        #    file.seek(1, os.SEEK_CUR)
    else: # Skip back
        file.seek(header.header_offset)

    # Probably a long file name directory - read and keep
    header = read_header() 
    if header.name == b'//':
        long_names = file.read(header.size)
        if header.size % 2 == 1:
            file.seek(1, os.SEEK_CUR)
    else: # It's a file, skip back
        file.seek(header.header_offset)
        
    # Read all file headers, build a list
    headers = list()
    while file.tell() < size:
        header = read_header()
        headers.append(header)
        skip_content(header)

    # Present the user with slice choice
    # TODO: encoding?
    names = tuple(h.name.rstrip(b'/').decode('ASCII') for h in headers)
    slice = resolve_slice(names, 'Static Library', 'Choose an object file:')
    if slice is None:
        return False # Cancellation
    
    header = headers[slice]
    file.seek(header.data_offset)
    b = file.read(header.size)
    # We support ELF and MachO static libraries so far
    if b[:4] == b'\x7FELF':
        di = read_elf(BytesIO(b), None)
    elif b[:4] in (b'\xFE\xED\xFA\xCE', b'\xFE\xED\xFA\xCF', b'\xCE\xFA\xED\xFE', b'\xCF\xFA\xED\xFE'):
        from filebytes.mach_o import MachO
        macho = MachO(None, b)
        di = get_macho_dwarf(macho, None)
    elif b[:4] == b'\xCA\xFE\xBA\xBE':
        raise FormatError("The selected slice of the static library is a Mach-O fat binary. Those are not supported. Let the author know.")
    else:
        raise FormatError("The selected slice of the static library is not a supported object file. Let the author know.")
    
    if di:
        di._format += 4
        di._fat_arch = names[slice]
    return di

# UI agnostic - resolve_arch might be interactive
# Returns slightly augmented DWARFInfo
# Or None if not a DWARF containing file (or unrecognized)
# Or False if user has cancelled
# Or throws an exception
# resolve_arch is for Mach-O fat binaries - see read_macho()
# and repurposed for .a static libraries
def read_dwarf(filename, resolve_arch):
    if path.isfile(filename): # On MacOS, opening dSYM bundles as is would be right, and they are technically folders
        with open(filename, 'rb') as file:
            xsignature = file.read(8)
            signature = xsignature[:4]

            if xsignature[:2] == b'MZ': # DOS header - this might be a PE. Don't verify the PE header, just feed it to the parser
                return read_pe(filename)
            elif signature == b'\x7FELF': #It's an ELF
                return read_elf(file, filename)
            elif signature in (b'\xCA\xFE\xBA\xBE', b'\xFE\xED\xFA\xCE', b'\xFE\xED\xFA\xCF', b'\xCE\xFA\xED\xFE', b'\xCF\xFA\xED\xFE'):
                if signature == b'\xCA\xFE\xBA\xBE' and int.from_bytes(file.read(4), 'big') >= 0x20:
                    # Java .class files also have CAFEBABE, check the fat binary arch count
                    return None
                # Mach-O fat binary, or 32/64-bit Mach-O in big/little-endian format
                return read_macho(filename, resolve_arch, filename)
            elif signature == b'\0asm':
                return read_wasm(file)
            elif xsignature == b'!<arch>\n':
                return read_staticlib(file, resolve_arch)
    elif path.isdir(filename):
        binary = binary_from_bundle(filename)
        if binary:
            return read_macho(binary, resolve_arch, filename)
        
def get_debug_sections(di):
    section_names = {name: "debug_%s_sec" % name
            for name in 
            ('info', 'aranges', 'abbrev', 'frame',
            'str', 'loc', 'ranges', 'line', 'addr',
            'str_offsets', 'line_str', 'pubtypes',
            'pubnames', 'loclists', 'rnglists', 'sup')}
    section_names['eh_frame'] = 'eh_frame_sec'
    section_names['gnu_debugaltlink'] = 'gnu_debugaltlink'

    # Display name to section object
    return {display_name: getattr(di, field_name)
        for (display_name, field_name) in section_names.items()
        if hasattr(di, field_name)}

    # TODO: unwind_info and text on macho
