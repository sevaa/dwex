from elftools.dwarf.descriptions import _REG_NAMES_x86, _REG_NAMES_x64, _REG_NAMES_AArch64
from elftools.dwarf.dwarf_expr import DWARFExprOp

# Source: https://github.com/ARM-software/abi-aa/blob/main/aadwarf32/aadwarf32.rst#dwarf-register-names
_REG_NAMES_ARM = [
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
] + ['<none>']*48 + ["s%d" %(n,) for n in range(32)] + [
    'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
    'wcgr0', 'wcgr1', 'wcgr2', 'wcgr3', 'wcgr4', 'wcgr5', 'wcgr6', 'wcgr7', 
    'acc0', 'acc1', 'acc2', 'acc3', 'acc4', 'acc5', 'acc6', 'acc7',
    'wr0', 'wr1', 'wr2', 'wr3', 'wr4', 'wr5', 'wr6', 'wr7',
    'wr8', 'wr9', 'wr10', 'wr11', 'wr12', 'wr13', 'wr14', 'wr15',
    'spsr', 'spsr_fiq', 'spsr_irq', 'spsr_abt', 'spsr_und', 'spsr_svc'] + ['<none>']*14 + [
    'ra_auth_code', 'r8_usr', 'r9_usr', 'r10_usr', 'r11_usr', 'r12_usr', 'r13_usr', 'r14_usr',
    'r8_fiq', 'r9_fiq', 'r10_fiq', 'r11_fiq', 'r12_fiq', 'r13_fiq', 'r14_fiq',
    'r8_irq', 'r9_irq', 'r10_irq', 'r11_irq', 'r12_irq', 'r13_irq', 'r14_irq',
    'r8_abt', 'r9_abt', 'r10_abt', 'r11_abt', 'r12_abt', 'r13_abt', 'r14_abt',
    'r8_und', 'r9_und', 'r10_und', 'r11_und', 'r12_und', 'r13_und', 'r14_und',
    'r8_svc', 'r9_svc', 'r10_svc', 'r11_svc', 'r12_svc', 'r13_svc', 'r14_svc'] + ['<none>']*24 + [
    'wc0', 'wc1', 'wc2', 'wc3', 'wc4', 'wc5', 'wc6', 'wc7'] + ['<none>']*55 + [
        "d%d" %(n,) for n in range(31)] + ['<none>']*21 + [
     'tpidruro', 'tpidrurw', 'tpidpr', 'htpidpr'
]

_REG_NAMES_MIPS = [
    '$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3',
    '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7',
    '$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7',
    '$t8', '$t9', '$k0', '$k1', '$gp', '$sp', '$fp', '$ra'
] # Lo, hi???

# More? 

# The key here is the machine_arch value in the DWARFConfig struct.
# Machine arch values are generated differently for ELF, MachO and PE
# For ELF, see the values in the architecture dict in get_machine_arch() under elftools.elf.elffile
# For PE, see IMAGE_FILE_MACHINE in filebytes.pe
# For MachO, see make_macho_arch_name() in formats.py, which derives from CpuType under filebytes.mach_o and subtypes

_REG_NAME_MAP = dict(
    x86 = _REG_NAMES_x86,
    I386 = _REG_NAMES_x86,
    x64 = _REG_NAMES_x64,
    AMD64 = _REG_NAMES_x64,
    X86_64 = _REG_NAMES_x64,
    ARM = _REG_NAMES_ARM,
    ARMV6 = _REG_NAMES_ARM,
    ARMV7 = _REG_NAMES_ARM,
    ARMV7A = _REG_NAMES_ARM,
    ARMV7S = _REG_NAMES_ARM,
    AArch64 = _REG_NAMES_AArch64,
    ARM64 = _REG_NAMES_AArch64,
    ARME = _REG_NAMES_AArch64,
    MIPS = _REG_NAMES_MIPS
)

class ExprFormatter:
    # Operator codes differ in DWARFv1, thus the need for version
    # regnames: False for friendly names, True for DWARF names
    # prefix: False for friendly, Trus for DW_OP_xxx
    def __init__(self, regnames, prefix, arch, dwarf_version):
        self.regnames = regnames
        self.prefix = prefix
        self.arch = arch
        self.regnamelist = _REG_NAME_MAP.get(self.arch)
        self.dwarf_version = dwarf_version # Likely to change

    def set_arch(self, arch):
        if arch != self.arch:
            self.arch = arch
            self.regnamelist = _REG_NAME_MAP.get(self.arch)        

    def format_arg(self, s):
        if isinstance(s, str):
            return s
        elif isinstance(s, int):
            return hex(s) if self.hex else str(s)
        elif isinstance(s, list): # Could be a blob (list of ints), could be a subexpression
            if len(s) > 0 and isinstance(s[0], DWARFExprOp): # Subexpression
                return '{' + '; '.join(self.format_op(*op) for op in s) + '}'
            else:
                return bytes(s).hex() # Python 3.5+

    def decode_breg(self, regno, offset):
        if offset == 0:
            return '[%s]' % (self.regnamelist[regno],)
        elif offset < 0:
            return '[%s-0x%x]' % (self.regnamelist[regno], -offset)
        else:
            return '[%s+0x%x]' % (self.regnamelist[regno], offset)

    def format_op(self, op, op_name, args, offset):
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

        if op_name.startswith('DW_OP_') and not self.prefix:
            op_name = op_name[6:]

        if args:
            return op_name + ' ' + ', '.join(self.format_arg(s) for s in args)
        else:
            return op_name

