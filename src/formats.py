import io, struct
from os import path
from elftools.dwarf.dwarfinfo import DWARFInfo, DebugSectionDescriptor, DwarfConfig
# This doesn't depend on Qt

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
    return DWARFInfo(
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

# resolve_arch takes a list of architecture descriptions, and returns
# the desired index, or None if the user has cancelled
def read_macho(filename, resolve_arch):
    from filebytes.mach_o import MachO, CpuType, CpuSubTypeARM, TypeFlags
    macho = MachO(filename)
    # TODO: find a MachO file that is not a fat binary
    if macho.isFat:
        # One CPU type where it's relevant - armv6, armv7, armv7s coexisted in the iOS toolchain for a while
        slices = [CpuType[slice.machHeader.header.cputype].name +
            (CpuSubTypeARM[slice.machHeader.header.cpusubtype].name if slice.machHeader.header.cputype == CpuType.ARM else '')
            for slice in macho.fatArches]
        arch_no = resolve_arch(slices)
        if arch_no is None: # User cancellation
            return False
        macho = macho.fatArches[arch_no]

    # We proceed with macho being a arch-specific file, or a slice within a fat binary
    data = {
        section.name: DebugSectionDescriptor(io.BytesIO(section.bytes), section.name, None, len(section.bytes), 0)
        for loadcmd in macho.loadCommands
        if getattr(loadcmd, 'name', None) == '__DWARF'
        for section in loadcmd.sections
    }

    if not '__debug_info' in data:
        return None

    # TODO: distinguish between arm flavors in DwarfConfig?
    arch = macho.machHeader.header.cputype
    return DWARFInfo(
        config = DwarfConfig(
            little_endian=True,
            default_address_size = 8 if (arch | TypeFlags.ABI64) != 0 else 4,
            machine_arch = CpuType[arch].name
        ),
        debug_info_sec = data['__debug_info'],
        debug_aranges_sec = data['__debug_aranges'],
        debug_abbrev_sec = data['__debug_abbrev'],
        debug_frame_sec = data.get('__debug_frame'),
        eh_frame_sec = None,
        debug_str_sec = data['__debug_str'],
        debug_loc_sec = data['__debug_loc'],
        debug_ranges_sec = data['__debug_ranges'],
        debug_line_sec = data['__debug_line'],
        debug_pubtypes_sec = data['__debug_pubtypes'],
        debug_pubnames_sec = data['__debug_pubtypes'],
    )

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
                return elffile.get_dwarf_info()
            elif struct.unpack('>I', signature)[0] in (0xcafebabe, 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe): # Mach-O fat binary, 32- and 64-bit Mach-O in big- or little-endian format
                return read_macho(filename, resolve_arch)
        finally:
            if file:
                file.close()                
    elif path.isdir(filename):
        # Is it a dSYM bundle?
        nameparts = path.basename(filename).split('.') # Typical bundle name: appname.app.dSYM
        dsym_file = path.join(filename, 'Contents', 'Resources', 'DWARF', nameparts[0])
        if path.exists(dsym_file):
            return read_macho(dsym_file, resolve_arch)
        # Any other bundle formats we should be aware of?
    return None
