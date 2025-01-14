from elftools.dwarf.descriptions import _REG_NAMES_x86, _REG_NAMES_x64, _REG_NAMES_AArch64
from elftools.dwarf.dwarf_expr import DWARFExprOp

# TODO: take from pyelftools when they publish
# Source: https://github.com/ARM-software/abi-aa/blob/main/aadwarf32/aadwarf32.rst#dwarf-register-names
_REG_NAMES_ARM = [
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
] + ['<none>']*48 + ["s%d" %(n,) for n in range(32)] + [
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
    'acc0', 'acc1', 'acc2', 'acc3', 'acc4', 'acc5', 'acc6', 'acc7', #AKA wcgr0..7
    'wr0', 'wr1', 'wr2', 'wr3', 'wr4', 'wr5', 'wr6', 'wr7',
    'wr8', 'wr9', 'wr10', 'wr11', 'wr12', 'wr13', 'wr14', 'wr15',
    'spsr', 'spsr_fiq', 'spsr_irq', 'spsr_abt', 'spsr_und', 'spsr_svc'] + ['<none>']*9 + [
    'ra_auth_code', 'r8_usr', 'r9_usr', 'r10_usr', 'r11_usr', 'r12_usr', 'r13_usr', 'r14_usr',
    'r8_fiq', 'r9_fiq', 'r10_fiq', 'r11_fiq', 'r12_fiq', 'r13_fiq', 'r14_fiq',
    'r13_irq', 'r14_irq', 'r13_abt', 'r14_abt',
    'r13_und', 'r14_und', 'r13_svc', 'r14_svc'] + ['<none>']*26 + [
    'wc0', 'wc1', 'wc2', 'wc3', 'wc4', 'wc5', 'wc6', 'wc7'] + ['<none>']*56 + [
        "d%d" %(n,) for n in range(32)] + ['<none>']*32 + [
     'tpidruro', 'tpidrurw', 'tpidpr', 'htpidpr'
]

_REG_NAMES_MIPS = [
    '$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3',
    '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7',
    '$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7',
    '$t8', '$t9', '$k0', '$k1', '$gp', '$sp', '$fp', '$ra',
    '$ps', '$lo', '$hi', '$badvaddr', '$cause', '$pc'] + [
        '$fp%d' % n for n in range(35)] + ['<none>'] + [
        '$cp%d' % n for n in range(15)] + ['$prid']

# Source: https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-dwarf.adoc
_REG_NAMES_RISCV = [
    'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
    'fp', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
    'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'] + [
        'f%d' % n for n in range(32)] + ['afrc'] + ['<none>']*31 + [
        'v%d' % n for n in range(32)]

# Source for 64 bit: https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-dwarf.adoc
# Source for 32 bit: http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf
# They are sufficiently similar
# There are some more kernel level registers defined in the ABI at #356 and further, not listed here
_REG_NAMES_POWERPC = ['r%d' % n for n in range(32)] +[
      'f%d' % n for n in range(32)] +[
    'cr', 'fpscr', 'msr', '<none>', '<none>', '<none>',
    'sr0', 'sr1', 'sr2', 'sr3', 'sr4', 'sr5', 'sr6', 'sr7',
    'sr8', 'sr9', 'sr10', 'sr11', 'sr12', 'sr13', 'sr14', 'sr15'] + ['<none>']*14 + [
    'mq', 'xer', '<none>', '<none>', 'rtcu', 'rtcl', '<none>', '<none>',
    'lr', 'ctr', '<none>', '<none>', '<none>', '<none>', '<none>', '<none>',
    '<none>', '<none>', 'dsisr', 'dar', '<none>', '<none>', 'dec', '<none>',
    '<none>', 'sdr1', 'srr0', 'srr1']

# More? 

# The key here is the machine_arch value in the DWARFConfig struct.
# Machine arch values are generated differently for ELF, MachO and PE
# For ELF, see the values in the architecture dict in get_machine_arch() under elftools.elf.elffile
# For PE, see IMAGE_FILE_MACHINE in filebytes.pe
# For MachO, see make_macho_arch_name() in formats.py, which derives from CpuType under filebytes.mach_o and subtypes

_REG_NAME_MAP = {
    'x86': _REG_NAMES_x86,
    'I386': _REG_NAMES_x86,
    'x64': _REG_NAMES_x64,
    'AMD64': _REG_NAMES_x64,
    'X86_64': _REG_NAMES_x64,
    'ARM': _REG_NAMES_ARM,
    'ARMV6': _REG_NAMES_ARM,
    'ARMV7': _REG_NAMES_ARM,
    'ARMV7A': _REG_NAMES_ARM,
    'ARMV7S': _REG_NAMES_ARM,
    'AArch64': _REG_NAMES_AArch64,
    'ARM64': _REG_NAMES_AArch64,
    'ARME': _REG_NAMES_AArch64,
    'MIPS': _REG_NAMES_MIPS,
    'RISC-V': _REG_NAMES_RISCV,
    'PowerPC': _REG_NAMES_POWERPC,
    '64-bit PowerPC': _REG_NAMES_POWERPC
}

class ExprFormatter:
    # Operator codes differ in DWARFv1, thus the need for version
    # regnames: False for friendly names, True for DWARF names
    # prefix: False for friendly, True for DW_OP_xxx
    # arch is for register name set selection
    # dwarf_version only matters whether it is 1 or greater
    # address_delta is the addend that will account for a custom loading address
    def __init__(self, regnames, prefix, arch, dwarf_version, hex):
        self.regnames = regnames
        self.prefix = prefix
        self.arch = arch
        self.regnamelist = _REG_NAME_MAP.get(self.arch)
        self.dwarf_version = dwarf_version # Likely to change
        self.hex = hex
        self.address_delta = 0
        self.cfa_resolver = None # no args, returns the CFA expression formatted to a string

    def set_arch(self, arch):
        if arch != self.arch:
            self.arch = arch
            self.regnamelist = _REG_NAME_MAP.get(self.arch)

    def set_address_delta(self, ad):
        self.address_delta = ad

    def decode_breg(self, regno, offset):
        if offset == 0:
            return '[%s]' % (self.regnamelist[regno],)
        elif -10 < offset < 0:
            return '[%s-%x]' % (self.regnamelist[regno], -offset)
        elif offset <= 10:
            return '[%s-0x%x]' % (self.regnamelist[regno], -offset)
        elif 0 < offset < 10:
            return '[%s+%x]' % (self.regnamelist[regno], offset)
        else:
            return '[%s+0x%x]' % (self.regnamelist[regno], offset)

    def format_op(self, op, op_name, args, offset):
        def format_arg(s):
            if isinstance(s, str):
                return s
            elif isinstance(s, int):
                # TODO: more discerning here, hex elsewhere?
                return hex(s) if (self.hex or op == 0x03) and not(-10 < s < 10) else str(s) 
            elif isinstance(s, list): # Could be a blob (list of ints), could be a subexpression
                if len(s) > 0 and isinstance(s[0], DWARFExprOp): # Subexpression
                    return '{' + '; '.join(self.format_op(*op) for op in s) + '}'
                else:
                    return bytes(s).hex() # Python 3.5+

        if not self.regnames and self.regnamelist: # Friendly register names
            if 0x50 <= op <= 0x6f and op - 0x50 < len(self.regnamelist): # reg0...reg31
                op_name = self.regnamelist[op-0x50]
            elif 0x70 <= op <= 0x8f and op - 0x70 < len(self.regnamelist) and len(args) > 0: # breg0...breg31(offset)
                op_name = self.decode_breg(op - 0x70, args[0])
                args = False
            elif (op == 0x90 or (self.dwarf_version == 1 and op == 0x1)) and len(args) > 0 and args[0] >= 0 and args[0] < len(self.regnamelist): # regx(regno)
                op_name = self.regnamelist[args[0]]
                args = False
            elif op == 0x92 and len(args) > 1 and args[0] >= 0 and args[0] < len(self.regnamelist): # bregx(regno, offset)
                op_name = self.decode_breg(args[0], args[1])
                args = False

        if op_name == 'DW_OP_call_frame_cfa' and self.cfa_resolver:
            resolved_cfa = self.cfa_resolver()
            if resolved_cfa:
               op_name += f"[{resolved_cfa}]"

        if op_name.startswith('DW_OP_') and not self.prefix:
            op_name = op_name[6:]

        if args:
            if op == 0x03: # DW_OP_addr: relocate
                args = [args[0] + self.address_delta]
            return op_name + ' ' + ', '.join(format_arg(s) for s in args)
        else:
            return op_name
        
    def regname(self, regno):
        return self.regnamelist[regno] if not self.regnames and self.regnamelist else "r%d" % (regno,)
    
    def format_regoffset(self, regno, offset):
        return self.regname(regno) + format_offset(offset)

# Hex or dec for small values
def format_offset(offset):
    if offset == 0 or offset is None:
        return ''
    elif 0 < offset < 0x10:
        return "+%d" % (offset,)
    elif -0x10 < offset < 0:
        return "-%d" % (-offset,)
    elif offset >= 0x10:
        return "+0x%x" % (offset,)
    else:
        return "-0x%x" % (-offset,)
    
def is_parsed_expression(l):
    """If the arg is a list, and the first element in the list is a DWARFExprOp
    """
    return isinstance(l, list) and len(l) and isinstance(l[0], DWARFExprOp)