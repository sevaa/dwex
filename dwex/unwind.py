from dwex.details import GenericTableModel
from .frames import FramesUIDlg
from .machounwind import MachoUnwindInfo


class UnwindDlg(FramesUIDlg):
    def __init__(self, win, unwind_section, di, hex):
        FramesUIDlg.__init__(self, win)
        if not hasattr(di, '_unwind_info'):
            uw = di._unwind_info = MachoUnwindInfo(unwind_section, di._arch_code)
        self.dwarfinfo = di
        self.decoded_entries = [uw.decode_entry(e) for p in di._unwind_info.pages if p.entries for e in p.entries]

        lines = [(hex(e.raw.address), hex(e.encoding), e.command, str(e.arg), e)
            for p in di._unwind_info.pages if p.entries
            for e in p.entries]
        self.entries.setModel(GenericTableModel(('Address', 'Encoding', 'Command', 'Argument(s)'), lines))
        self.entries.selectionModel().currentChanged.connect(self.on_entry_sel)

    def on_entry_sel(self, index, prev = None):
        entry = self.entry.model().values()[index.row()][-1]
        de = self.dwarfinfo._unwind_info.decode_entry(entry)
        #self.details.setModel(GenericTableModel()))

    