#!/usr/bin/env python
#-------------------------------------------------------------------------------
#
# A parser for the Mach-O __unwind_info section, based on format description from:
# https://faultlore.com/blah/compact-unwinding/
# https://github.com/llvm-mirror/libunwind/blob/master/include/mach-o/compact_unwind_encoding.h
# Lehmer code implementation taken from https://github.com/mateuszchudyk/lehmer/
#
# Seva Alekseyev (sevaa@sprynet.com)
# This code is in the public domain
#-------------------------------------------------------------------------------

from bisect import bisect_left
from collections import namedtuple
from enum import Enum
from struct import unpack_from

# MachO cputype values that we care for
class CpuType(Enum):
    I386 = 7
    X86_64 = 0x01000007
    ARM = 0xc
    ARM64 = 0x0100000c

Header = namedtuple('Header', ('version', 'global_encodings_offset', 'global_encodings_length', 'personalities_offset', 'personalities_length', 'pages_offset', 'pages_length'))
PageHeader = namedtuple('PageHeader', ('first_address', 'second_level_page_offset', 'lsda_index_offset'))
Page = namedtuple('Page', ('header', 'entries'))
LSDA = namedtuple('LSDA', ('instruction_address', 'lsda_address'))
UnwindEntry = namedtuple('UnwindEntry', ('address', 'encoding', 'command', 'arg'))
PushOrderARM64 = (19, 21, 23, 25, 27, 8, 10, 12, 14) 
RegOrderx86 = (3, 1, 2, 7, 6, 5) # ebx ecx edx edi esi ebp
RegOrderx64 = (3, 12, 13, 14, 15, 6) # rbx r12 r13 r14 r15 rbp
DecodedEntry = namedtuple('DecodedEntry', ('raw', 'has_frame', 'cfa_base_register', 'cfa_offset', 'saved_registers'))
FallbackEntry = namedtuple('FallbackEntry', ('raw', 'offset'))
NopEntry = namedtuple('NopEntry', ('raw'))

# AArch64 calling convention: 19-29 callee saved, x29=fp, x30=lr, x31=sp
class UnwindCommandARM64(Enum):
    Nop = 0
    # There is code there, but the stack structure is unknown

    Frameless = 2
    # x29 untouched, LR is the return address
    # SP reduced by (arg*16)
    # I don't have a sample

    EH = 3
    # Fallback to eh_frame, arg is FDE offset in eh_frame

    Frame = 4
    # arg is a tuple of 9 booleans, if the respective reg pair was saved in the prologue
    # Register pair order in the arg tuple:
    # 19/20 21/22 23/24 25/26 27/29 8/9 10/11 12/13 14/15
    # If they are pushed, they are pushed in this order, so offsets from sp go in the opposite order
    
class UnwindCommandIntel(Enum):
    Nop = 0

    Frame = 1
    # arg is a tuple of (offset, saved_regs)
    # where saved_regs is a a tuple of 5 register numbers
    # numbers correspond to either
    # None ebx ecx edx edi esi ebp
    # Or
    # None rbx r12 r13 r14 r15 rbp

    FramelessImmediate = 2
    # arg is a tuple of (stack_size, register_count, permutation)
    
    FramelessIndirect = 3
    # arg is a tuple of (instruction_offset, stack_adjust, reg_count, permutation)

    EH = 4
    # arg is the offset of the FDE in the eh_frame section

def tranlate_encoding_arm64(address, enc):
    """
        From encoding to a parsed operation. LSDA/personality stuff ignored.
    """
    # is_start = (enc & 0x80000000) != 0
    # has_lsda = (enc & 0x40000000) != 0
    # personality_index = (enc >> 28) & 3    
    cmd = UnwindCommandARM64((enc >> 24) & 0xf)
    if cmd == UnwindCommandARM64.Nop:
        arg = None
    elif cmd == UnwindCommandARM64.Frameless:
        arg = (enc >> 12) & 0xfff # Stack size
    elif cmd == UnwindCommandARM64.EH:
        arg = enc & 0xffffff # Offset in the eh_frame section
    elif cmd == UnwindCommandARM64.Frame:
        arg = tuple((enc & (1 << i)) != 0 for i in range(9)) # Map of which register pairs were saved on the stack
    # Else enum will raise an error
    return UnwindEntry(address, enc, cmd, arg)

def translate_encoding_intel(address, enc):
    """
        From encoding to a parsed operation. LSDA/personality stuff ignored. The x86/x64 distinction is irrelevant here.
    """
    # is_start = (enc & 0x80000000) != 0
    # has_lsda = (enc & 0x40000000) != 0
    # personality_index = (enc >> 28) & 3    
    cmd = UnwindCommandIntel((enc >> 24) & 0xf)
    if cmd == UnwindCommandIntel.Nop:
        arg = None
    elif cmd == UnwindCommandIntel.Frame:
        offset = (enc >> 16) & 0xff
        regs = tuple((enc >> i) & 7 for i in range(12, -3, -3))
        arg = (offset, regs)
    elif cmd == UnwindCommandIntel.FramelessImmediate:
        size = (enc >> 16) & 0xff
        n = (enc >> 10) & 7
        p = enc & 0x3f
        arg = (size, n, p)
    elif cmd == UnwindCommandIntel.FramelessIndirect:
        offset = (enc >> 16) & 0xff
        adj = (enc >> 13) & 7
        n = (enc >> 10) & 7
        p = enc & 0x3f
        arg = (offset, adj, n, p)
    elif cmd == UnwindCommandIntel.EH:
        arg = enc & 0xffffff # Offset in the eh_frame section
    return UnwindEntry(address, enc, cmd, arg)

class MachoUnwindInfo:
    """
    Holds the parsed unwind_info section. The LSDA/personality stuff is not decoded, with some stubs in place.
    Call find_by_address() to locate the unwind entry for a particular location in code.
    """
    def __init__(self, section_data, cputype, big_endian = False, text_section = None):
        """
        section_data:
            A bytes or a Buffer-compatible object with the unwind_info section contents

        cputype:
            The machine architecture code from the MachO file or fat slice header

        big_endian:
            True for a big-endian MachO file or fat slice, False for little-endian.
            To determine, check the magic in the MachO header: 0xfeedface and 0xfeedfacf are big endian.
            All three supported architectures use little endian on Apple platforms, so this is rather irrelevant.

        text_section:
            Reserved for when Intel FramelessIndirect decoding will be supported
        """
        cputype = CpuType(cputype)
        if cputype == CpuType.ARM64:
            translate_encoding = tranlate_encoding_arm64
            self.decode_entry = self.decode_entry_arm64
        elif cputype == CpuType.I386:
            translate_encoding = translate_encoding_intel
            self.decode_entry = lambda e: self.decode_entry_intel(e, 4, RegOrderx86, 5, 4, 8)
        elif cputype == CpuType.X86_64:
            translate_encoding = translate_encoding_intel
            self.decode_entry = lambda e: self.decode_entry_intel(e, 8, RegOrderx64, 6, 7, 16)
        else:
            raise NotImplementedError("Only x86, x86_64, and ARM64 are currently supported")
        self.cputype = cputype
        self.text = text_section

        endianness = '>' if big_endian else '<'
        self.header = header = Header(*unpack_from(endianness + 'IIIIIII', section_data, 0))
        page_headers = [PageHeader(*unpack_from(endianness + 'III', section_data, header.pages_offset + i*12)) for i in range(header.pages_length)]
        global_encodings = unpack_from(endianness + 'I'*header.global_encodings_length, section_data, header.global_encodings_offset)
        #personalities = unpack_from(endianness + 'I'*rph.personalities_length, unw, rph.personalities_offset)
        #lsda_offset = rph.pages_offset + rph.pages_length*12
        
        def process_page(page_header):
            page_offset = page_header.second_level_page_offset
            if page_offset: # Zero is possible in the final guard page that stores the effective end address
                (kind,) = unpack_from(endianness + 'I', section_data, page_offset)
                if kind == 2: # Regular second level page
                    (entries_offset, entries_length) = unpack_from(endianness + 'HH', section_data,  + 4)
                    entries = [translate_encoding(*unpack_from(endianness + 'II', section_data, page_offset + entries_offset + i*8)) for i in range(entries_length)]
                elif kind == 3: # Compressed second level page
                    (entries_offset, entries_length, encodings_offset, encodings_length) = unpack_from(endianness + 'HHHH', section_data, page_offset + 4)
                    raw_entries = unpack_from(endianness + 'I'*entries_length, section_data, page_offset + entries_offset)
                    encodings = unpack_from(endianness + 'I'*encodings_length, section_data, page_offset + encodings_offset)
                    all_encodings = global_encodings + encodings # :(
                    entries = [translate_encoding(page_header.first_address + e & 0xFFFFFF, all_encodings[(e>>24) & 0xff]) for e in raw_entries]
                else:
                    raise NotImplementedError(f"Unknown second level page kind {kind}")
            else:
                entries = None
            return Page(page_header, entries)
        
        self.pages = [process_page(page_header) for page_header in page_headers]

    def decode_entry_arm64(self, entry):
        cmd = entry.command
        if cmd == UnwindCommandARM64.Nop:
            return NopEntry(entry)
        elif cmd == UnwindCommandARM64.Frameless:
            return DecodedEntry(entry, False, 31, entry.arg, {})
        elif cmd == UnwindCommandARM64.EH:
            return FallbackEntry(entry, entry.arg)
        elif cmd == UnwindCommandARM64.Frame:
            # CFA at x29+16, x30 at CFA-16 x31 at CFA-8
            regs = {30: 16, 31: 8}
            off = 32
            for (i, r) in enumerate(entry.arg):
                if r:
                    base_regno = PushOrderARM64[i]
                    regs[base_regno] = off
                    regs[base_regno+1] = off - 8
                    off += 16
            return DecodedEntry(entry, True, 29, 16, regs)

    def decode_entry_intel(self, entry, rsize, arch_regmap, bp_regno, sp_regno, ip_regno):
        cmd = entry.command
        if cmd == UnwindCommandIntel.Nop:
            return NopEntry(entry)
        elif cmd == UnwindCommandIntel.Frame:
            # CFA at Xbp + 2*rsize
            # Saved Xbp at CFA-2*rsize (Xbp)
            # Return address at CFA-rsize (Xbp+rsize)
            # Registers go from CFA-3*rsize (Xbp-rsize) and up

            # Haven't seen cases where offset is not the same as the 5 minus count of leading zeros in the saved register array
            (offset, saved_regs) = entry.arg  # len(saved_regs) is 5
            regs = {bp_regno: 2*rsize, ip_regno: rsize}
            for (i, r) in enumerate(saved_regs):
                if r and i >= 5 - offset:
                    regs[arch_regmap[r-1]] = (i-2 + offset)*rsize
            return DecodedEntry(entry, True, bp_regno, 2*rsize, regs)
        elif cmd == UnwindCommandIntel.FramelessImmediate:
            raise NotImplementedError("Intel/FramelessImmediate is not supported yet")

            # CFA at Xsp + stack_size*rsize
            # return address at CFA-rsize
            # Pushed registers above that in the permutation order
            (stack_size, reg_count, permutation) = entry.arg
            regs = {ip_regno: rsize}
            if reg_count:
                pass
                #permutation = lehmer_decode(reg_count, permutation)
                #for (i, p) in enumerate(permutation):
                #    regs[arch_regmap[p]] = (2+i)*rsize
            return DecodedEntry(entry, False, sp_regno, stack_size*rsize, regs)
        elif cmd == UnwindCommandIntel.FramelessIndirect:
            raise NotImplementedError("Intel/FramelessIndirect is not supported yet")

            # x86_64 sub rsp, imm32 goes: 48 81 ec (imm32)
            # x86 sub esp, imm32 goes: 81 ec (imm32)            
            (instruction_offset, stack_adjust, reg_count, permutation) = entry.arg
            regs = {}
            if reg_count:
                permutation = lehmer_decode(reg_count, permutation)
                regs = {}
                # TODO the rest once I get an example
            else:
                regs = {}
            return DecodedEntry(entry, False, sp_regno, stack_size*rsize, regs)
        elif cmd == UnwindCommandIntel.EH:
            return FallbackEntry(entry, entry.arg)
    
    def find_by_address_raw(self, IP):
        """
            IP is relative to the preferred start address, as seen in the load segment command for the __TEXT segment.
            Returns a DecodedEntry, or None if the IP can't be found or the entry is a null one, or False if fallback to EH is in order
        """
        # TODO: key
        i = bisect_left([p.header.first_address for p in self.pages], IP)
        if i:
            entries = self.pages[i-1].entries
            i = bisect_left([e.address for e in entries], IP) - 1 # Supposed to be sorted
            return entries[i]

    def find_by_address(self, IP):
        """
            IP is relative to the preferred start address, as seen in the load segment command for the __TEXT segment.
            Returns:
                - None if the IP can't be found (doesn't distinguish between first level and second level lookup fails)
                - DecodedEntry
                - FallbackEntry (with "offset" being offset of the FDE in the eh_frame section, but mind the address interpretation)
                - NopEntry

            DecodedEntry fields are:
             - has_frame - whether a dedicated register (r29, rbp, ebp) is used for this function's frame base
             - cfa_base_register - DWARF number of the register that the CFA is relative to
             - cfa_offset - offset from the cfa_base_register to the CFA
             - saved_registers - maps DWARF register number to the offset (negative) from CFA where it is saved
        """
        return self.decode_entry(self.find_by_address_raw(IP))
    
_fact = (1, 1, 2, 6, 24, 120, 720)
def factorial(n):
    return _fact[n]

def lehmer_decode(length, lehmer):
    """Return permutation for the given Lehmer Code and permutation length. Result permutation contains
    number from 0 to length-1.
    """
    result = [(lehmer % factorial(length - i)) // factorial(length - 1 - i) for i in range(length)]
    used = [False] * length
    for i in range(length):
        counter = 0
        for j in range(length):
            if not used[j]:
                counter += 1
            if counter == result[i] + 1:
                result[i] = j
                used[j] = True
                break
    return result
