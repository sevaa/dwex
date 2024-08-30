from PyQt6.QtCore import Qt, QAbstractTableModel
from PyQt6.QtWidgets import *

from .dwarfutil import top_die_file_name

headers = ["Start address", "Length", 'CU offset', 'Source name']

# TODO: low level view?

class AraModel(QAbstractTableModel):
    def __init__(self, ara, di):
        QAbstractTableModel.__init__(self)
        self.entries = ara.entries
        self.dwarfinfo = di

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return headers[section]

    def rowCount(self, parent):
        return len(self.entries)

    def columnCount(self, parent):
        return 4
    
    def data(self, index, role):
        (row, col) = (index.row(), index.column())
        entry = self.entries[row]
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return hex(entry.begin_addr)
            elif col == 1:
                return hex(entry.length)
            elif col == 2:
                return hex(entry.info_offset)
            elif col == 3:
                cu = self.dwarfinfo.get_CU_at(entry.info_offset)
                return top_die_file_name(cu.get_top_DIE())

######################################################################################

# TODO: sort by header click

class ArangesDlg(QDialog):
    def __init__(self, win, ara, di):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.selected_cu_offset = False
        self.resize(500, 500)
        ly = QVBoxLayout()

        self.the_table = QTableView()
        self.the_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.the_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.the_table.setModel(AraModel(ara, di))
        self.the_table.selectionModel().currentChanged.connect(self.on_sel)
        self.the_table.doubleClicked.connect(self.navigate_to_index)
        self.the_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        ly.addWidget(self.the_table)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        self.nav_bu = QPushButton("Navigate", self)
        self.nav_bu.clicked.connect(lambda: self.navigate_to_index(self.the_table.currentIndex()))
        self.nav_bu.setEnabled(False)
        buttons.addButton(self.nav_bu, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)

        self.setWindowTitle('Aranges')
        self.setLayout(ly)

    def on_sel(self, index, prev = None):
        self.nav_bu.setEnabled(index.isValid())

    def navigate_to_index(self, index):
        row = index.row()
        self.selected_cu_offset = self.the_table.model().entries[row].info_offset
        self.done(QDialog.DialogCode.Accepted)
