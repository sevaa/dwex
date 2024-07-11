from collections import namedtuple
import io, os
from os import path, listdir
from elftools.dwarf.dwarfinfo import DWARFInfo, DebugSectionDescriptor, DwarfConfig
# This doesn't depend on Qt
# The dependency on filebytes only lives here
# Format codes: 0 = ELF, 1 = MACHO, 2 = PE, 3 - WASM, 4 - ELF inside A

class FormatError(Exception):
    def __init__(self, s):
        Exception.__init__(self, s)

def read_pe(filename):
    from filebytes.pe import PE, IMAGE_FILE_MACHINE

    pefile = PE(filename)

    # Section's real size might be padded - see https://github.com/sashs/filebytes/issues/28
    sections = [(section.name, section,
        section.header.PhysicalAddress_or_VirtualSize,
        section.header.SizeOfRawData)
        for section in pefile.sections
        if section.name.startswith('.debug')]

    data = {name: DebugSectionDescriptor(io.BytesIO(section.bytes), name, None,
            raw_size if virtual_size == 0 else min((raw_size, virtual_size)), 0)
        for (name, section, virtual_size, raw_size) in sections}

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
        eh_frame_sec = None, # Haven't seen one in the wild so far
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
    di._start_address = pefile.imageNtHeaders.header.OptionalHeader.ImageBase
    return di

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
    from filebytes.mach_o import MachO, CpuType, TypeFlags, LC
    fat_arch = None
    macho = MachO(filename)
    if macho.isFat:
        slices = [make_macho_arch_name(slice) for slice in macho.fatArches]
        arch_no = resolve_arch(slices, 'Mach-O Fat Binary', 'Choose an architecture:')
        if arch_no is None: # User cancellation
            return False
        fat_arch = slices[arch_no]
        macho = macho.fatArches[arch_no]

    # We proceed with macho being a arch-specific file, or a slice within a fat binary
    data = {
        section.name: DebugSectionDescriptor(io.BytesIO(section.bytes), section.name, None, len(section.bytes), 0)
        for cmd in macho.loadCommands
        if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64)
        for section in cmd.sections
        if section.name.startswith('__debug')
    }

    #macho_save_sections(friendly_filename, macho)

    if not '__debug_info' in data:
        return None

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
        eh_frame_sec = None, # Haven't seen those in Mach-O
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
    di._format = 1
    di._fat_arch = fat_arch
    text_cmd = next((cmd for cmd in macho.loadCommands if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64) and cmd.name == "__TEXT"), False)
    di._start_address = text_cmd.header.vmaddr if text_cmd else 0
    return di

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
    di._start_address = 0
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
        di = elffile.get_dwarf_info()
    elif elffile.get_section_by_name(".debug"):
        from .dwarfone import parse_dwarf1
        di = parse_dwarf1(elffile)

    if di:
        di._format = 0
        di._start_address = start_address
    return di

_ar_file_header = namedtuple('ARHeader', ('data_offset', 'name', 'mod', 'uid', 'gid', 'mode', 'size'))

# resolve_slice takes a list of files in the archive, and returns
# the desired index, or None if the user has cancelled
def read_staticlib(file, resolve_slice):
    from io import BytesIO
    long_names = False
    def read_header():
        b = file.read(60)
        data_offset = file.tell()
        name = b[0:16].rstrip()
        # Resolve GNU style long file names
        if name.startswith(b'/') and len(name) > 1 and ord(b'0') <= name[1] <= ord(b'9'):
            if not long_names:
                FormatError("Long file name in a static library, but no long name section was found.")
            str_offset = int(name[1:])
            end_pos = long_names.find(b'\n', str_offset)
            name = long_names[str_offset:end_pos] if end_pos >= 0 else long_names[str_offset:]
        return _ar_file_header(data_offset, name,
                               int(b[16:28]), int(b[28:34]),
                               int(b[34:40]), int(b[40:48], 8),
                               int(b[48:58]))

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(8, os.SEEK_SET)

    # First section most likely a symtab - skip
    header = read_header() 
    if header.name == b'/' or header.name == b'/SYM64/':
        file.seek(((header.size + 1) // 2) * 2, os.SEEK_CUR)
    else: # Skip back
        file.seek(-60, os.SEEK_CUR)

    # Probably a long file name directory - read and keep
    header = read_header() 
    if header.name == b'//':
        long_names = file.read(header.size)
        if header.size % 2 == 1:
            file.seek(1, os.SEEK_CUR)
    else: # It's a file, skip back
        file.seek(-60, os.SEEK_CUR)
        
    # Read all file headers, build a list
    headers = list()
    while file.tell() < size:
        header = read_header()
        headers.append(header)
        file.seek(((header.size + 1) // 2) * 2, os.SEEK_CUR)

    # Present the user with slice choice
    # TODO: encoding?
    names = list(h.name[:-1].decode('ASCII') for h in headers)
    slice = resolve_slice(names, 'Static Library', 'Choose an object file:')
    if slice is None:
        return False # Cancellation
    
    header = headers[slice]
    file.seek(header.data_offset)
    di = read_elf(BytesIO(file.read(header.size)), None)
    if di:
        di._format = 4
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
        # Is it a dSYM bundle?
        nameparts = path.basename(filename).split('.') 
        if nameparts[-1] == 'dSYM' and path.exists(path.join(filename, 'Contents', 'Resources', 'DWARF')):
            files = listdir(path.join(filename, 'Contents', 'Resources', 'DWARF'))
            if len(files) > 0:
                # When are there multiple DWARF files in a dSYM bundle?
                # TODO: let the user choose?
                dsym_file_path = path.join(filename, 'Contents', 'Resources', 'DWARF', files[0])
                return read_macho(dsym_file_path, resolve_arch, filename)
        # Is it an app bundle? appname.app
        if len(nameparts) > 1 and nameparts[-1] in ('app', 'framework'):
            app_file = path.join(filename, '.'.join(nameparts[0:-1]))
            if path.exists(app_file):
                return read_macho(app_file, resolve_arch, filename)

        # Any other bundle formats we should be aware of?
    return None

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
        if getattr(di, field_name, False)}    
