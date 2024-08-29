from PyQt6.QtCore import Qt, QAbstractTableModel
from PyQt6.QtWidgets import *

from .dwarfutil import safe_DIE_name

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
                return safe_DIE_name(cu.get_top_DIE(), '?')

class ArangesDlg(QDialog):
    def __init__(self, win, ara, di):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.resize(500, 400)
        ly = QVBoxLayout()

        self.the_table = QTableView()
        self.the_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.the_table.setModel(AraModel(ara, di))
        # self.the_table.doubleClicked.connect(self.on_dclick)
        ly.addWidget(self.the_table)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        #self.nav_bu = QPushButton("Navigate", self)
        #self.nav_bu.clicked.connect(self.on_navigate)
        #self.nav_bu.setEnabled(False)
        #buttons.addButton(self.nav_bu, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)

        self.setWindowTitle('Aranges')
        self.setLayout(ly)        
