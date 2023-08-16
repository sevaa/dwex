from elftools.dwarf.descriptions import _REG_NAMES_x86, _REG_NAMES_x64
from elftools.dwarf.dwarf_expr import DWARFExprOp

_REG_NAMES_ARM = [
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
    # Ever higher values for FP or SIMD registers?
]

# TODO: check against readelf, not sure
_REG_NAMES_ARM64 = [
    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
    'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31'
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
# For MachO, see make_macho_arch_name() in formats.py

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
    AArch64 = _REG_NAMES_ARM64,
    ARM64 = _REG_NAMES_ARM64,
    ARME = _REG_NAMES_ARM64,
    MIPS = _REG_NAMES_MIPS
)

class ExprFormatter:
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

