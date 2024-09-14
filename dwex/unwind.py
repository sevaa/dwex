from dwex.details import GenericTableModel
from PyQt6.QtWidgets import QHeaderView
from .frames import FramesUIDlg
from .machounwind import MachoUnwindInfo, UnwindCommandARM64, UnwindCommandIntel, NopEntry, FallbackEntry
from .exprutil import _REG_NAME_MAP, format_offset

def format_arg(e):
    if e.arg is None:
        return ''
    elif e.command == UnwindCommandARM64.Frame:
        return ''.join(str(int(b)) for b in e.arg)
    else:
        return str(e.arg)

class UnwindDlg(FramesUIDlg):
    def __init__(self, win, unwind_section, di, regnames, hex_):
        FramesUIDlg.__init__(self, win)
        if hasattr(di, '_unwind_info'):
            uw = di._unwind_info
        else:
            uw = di._unwind_info = MachoUnwindInfo(unwind_section, di._arch_code[0])

        self.dwarfinfo = di
        self.regnames = _REG_NAME_MAP.get(di.config.machine_arch, None) if not regnames else None

        lines = [(hex(di._start_address + e.address), hex(e.encoding), e.command.name, format_arg(e), e)
            for p in uw.pages if p.entries for e in p.entries]
        self.entries.setModel(GenericTableModel(('Address', 'Encoding', 'Command', 'Argument(s)'), lines))
        self.entries.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.entries.selectionModel().currentChanged.connect(self.on_entry_sel)

    def on_entry_sel(self, index, prev = None):
        try:
            entry = self.entries.model().values[index.row()][-1]
            de = self.dwarfinfo._unwind_info.decode_entry(entry)
            if isinstance(de, NopEntry):
                headers = ('',)
                values = (('Unknown frame structure',),)
            elif isinstance(de, FallbackEntry):
                headers = ('',)
                values = (('See under Frames',),)
            else:
                # The assumption is that if LR is not saved, it's preserved.
                # Losing LR altogether can only happen in a noreturn function, which is unlikely.
                headers = ('CFA',) + tuple(self.regname(rno) for rno in de.saved_registers.keys())
                value = (self.regname(de.cfa_base_register) + format_offset(de.cfa_offset),)
                value += tuple(f"[CFA{format_offset(-off)}]" for off in de.saved_registers.values())
                values = (value,)
        except NotImplementedError:
            headers = ('',)
            values = (('Not supported yet.',),)
        self.details.setModel(GenericTableModel(headers, values))

    def regname(self, regno):
        return self.regnames[regno] if self.regnames else f"r{regno}"

    