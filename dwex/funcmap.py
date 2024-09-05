from PyQt6.QtCore import Qt, QThread, pyqtSignal
from bisect import bisect_left
from PyQt6.QtWidgets import *

from .details import GenericTableModel
from .dwarfutil import get_code_location, has_code_location, subprogram_name
from .locals import LoadedModuleDlgBase, WaitCursor

# TODO: unite UI with aranges - dialog with a table and potentially a search bar
# TODO: sorting

class GatherFuncsThread(QThread):
    def __init__(self, parent, di):
        QThread.__init__(self, parent)
        self.cancelled = False
        self.funcs = None
        self.exc = None
        self.dwarfinfo = di

    progress = pyqtSignal(int)

    def cancel(self):
        self.cancelled = True

    def run(self):
        try:
            funcs = []
            for cu in self.dwarfinfo._unsorted_CUs:
                for die in cu.iter_DIEs():
                    self.yieldCurrentThread()
                    if self.cancelled:
                        return

                    if die.tag in ('DW_TAG_subprogram', 'DW_TAG_global_subroutine') and has_code_location(die):
                        self.progress.emit(die.offset)
                        IP = get_code_location(die).start_address()
                        i = bisect_left(funcs, IP, key=lambda f:f[3])
                        funcs.insert(i, (hex(IP), subprogram_name(die), die, IP))
            self.funcs = funcs
        except Exception as exc:
            self.exc = exc


class FuncMapDlg(LoadedModuleDlgBase):
    def __init__(self, win, hex, funcs):
        LoadedModuleDlgBase.__init__(self, win)
        self.selected_die = None
        model = GenericTableModel(("Start address", 'Function'), funcs)

        self.resize(500, 500)
        ly = QVBoxLayout()

        self.the_table = QTableView()
        self.the_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.the_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.the_table.setModel(model)
        self.the_table.selectionModel().currentChanged.connect(self.on_sel)
        self.the_table.doubleClicked.connect(self.navigate_to_index)
        self.the_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        ly.addWidget(self.the_table)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        self.nav_bu = QPushButton("Navigate", self)
        self.nav_bu.clicked.connect(lambda: self.navigate_to_index(self.the_table.currentIndex()))
        self.nav_bu.setEnabled(False)
        buttons.addButton(self.nav_bu, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)

        self.setWindowTitle('Function map')
        self.setLayout(ly)

    def on_sel(self, index, prev = None):
        self.nav_bu.setEnabled(index.isValid())

    def navigate_to_index(self, index):
        row = index.row()
        self.selected_die = self.the_table.model().values[row][2]
        self.done(QDialog.DialogCode.Accepted)
        