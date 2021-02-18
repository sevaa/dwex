import io, struct
from os import path
from elftools.dwarf.dwarfinfo import DWARFInfo, DebugSectionDescriptor, DwarfConfig
# This doesn't depend on Qt
# The dependency on filebytes only lives here
# Format codes: 0 = ELF, 1 = MACHO, 2 = PE

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
        eh_frame_sec = None, # Haven't see one in the wild so far
        debug_str_sec = data.get('.debug_str'),
        debug_loc_sec = data.get('.debug_loc'),
        debug_ranges_sec = data.get('.debug_ranges'),
        debug_line_sec = data.get('.debug_line'),
        debug_pubtypes_sec = data.get('.debug_pubtypes'),
        debug_pubnames_sec = data.get('.debug_pubnames'),
    )
    di._format = 2
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
        arch_no = resolve_arch(slices)
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
    )
    di._format = 1
    di._fat_arch = fat_arch
    text_cmd = next((cmd for cmd in macho.loadCommands if cmd.header.cmd in (LC.SEGMENT, LC.SEGMENT_64) and cmd.name == "__TEXT"), False)
    di._start_address = text_cmd.header.vmaddr if text_cmd else 0
    return di

# UI agnostic - resolve_arch might be interactive
# Returns DWARFInfo
# Or None if not a DWARF containing file (or unrecognized)
# Or False if user has cancelled
# Or throws an exception
# resolve_arch is for Mach-O fat binaries - see read_macho()
def read_dwarf(filename, resolve_arch):
    if path.isfile(filename): # On MacOS, opening dSYM bundles as is would be right
        file = None
        try: # For ELF, the file is to remain open
            file = open(filename, 'rb')
            signature = file.read(4)

            if signature[0:2] == b'MZ': # DOS header - this might be a PE. Don't verify the PE header, just feed it to the parser
                return read_pe(filename)
            elif signature == b'\x7FELF': #It's an ELF
                from elftools.elf.elffile import ELFFile
                file.seek(0)
                elffile = ELFFile(file)
                file = None # Keep the file open
                if elffile.has_dwarf_info():
                    di = elffile.get_dwarf_info()
                    di._format = 0
                    return di
                elif elffile.get_section_by_name(".debug"):
                    from .dwarfone import parse_dwarf1
                    di = parse_dwarf1(elffile)
                    di._format = 0
                    return di
                else:
                    return None
            elif struct.unpack('>I', signature)[0] in (0xcafebabe, 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe):
                # Mach-O fat binary, or 32/64-bit Mach-O in big/little-endian format
                return read_macho(filename, resolve_arch, filename)
        finally:
            if file:
                file.close()                
    elif path.isdir(filename):
        # Is it a dSYM bundle?
        nameparts = path.basename(filename).split('.') # Typical bundle name: appname.app.dSYM
        if len(nameparts) > 2 and nameparts[-2] in ('app', 'framework') and nameparts[-1] == 'dSYM':
            dsym_file = path.join(filename, 'Contents', 'Resources', 'DWARF', nameparts[0])
            if path.exists(dsym_file):
                return read_macho(dsym_file, resolve_arch, filename)
        # Is it an app bundle? appname.app
        if len(nameparts) > 1 and nameparts[-1] in ('app', 'framework'):
            app_file = path.join(filename, nameparts[0])
            if path.exists(app_file):
                return read_macho(app_file, resolve_arch, filename)


        # Any other bundle formats we should be aware of?
    return None
