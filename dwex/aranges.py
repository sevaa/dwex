from PyQt6.QtCore import Qt, QAbstractTableModel
from PyQt6.QtWidgets import *

from .details import GenericTableModel
from .dwarfutil import top_die_file_name

# TODO: low level view?
# TODO: sort by header click

class ArangesDlg(QDialog):
    def __init__(self, win, ara, di, use_hex):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.selected_cu_offset = False
        self.resize(650, 500)

        lines = [(hex(entry.begin_addr),
                    hex(entry.begin_addr + entry.length - 1),
                    hex(entry.length) if use_hex else str(entry.length),
                    hex(entry.info_offset),
                    top_die_file_name(di.get_CU_at(entry.info_offset).get_top_DIE()),
                    entry.info_offset)
                    for entry in ara.entries]
        model = GenericTableModel(("Start address", "End address", "Length", 'CU offset', 'Source name'), lines)

        ly = QVBoxLayout()

        self.the_table = QTableView()
        self.the_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.the_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.the_table.setModel(model)
        self.the_table.selectionModel().currentChanged.connect(self.on_sel)
        self.the_table.doubleClicked.connect(self.navigate_to_index)
        self.the_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
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
        self.selected_cu_offset = self.the_table.model().values[row][-1]
        self.done(QDialog.DialogCode.Accepted)
