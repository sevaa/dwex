from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QAbstractTableModel

HEADERS = ('#', 'Offset', 'Operation')

class ExpressionModel(QAbstractTableModel):
    def __init__(self, expr, formatter):
        QAbstractTableModel.__init__(self)
        self.expr = expr
        self.formatter = formatter

    def rowCount(self, parent):
        return len(self.expr)

    def columnCount(self, parent):
        return 3
    
    def headerData(self, col, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return HEADERS[col]
    
    def index(self, row, col, parent):
        return self.createIndex(row, col, self.expr[row])
    
    def data(self, index, role):
        col = index.column()
        op = index.internalPointer()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(index.row() + 1)
            elif col == 1:
                return hex(op.offset)
            else:
                return self.formatter.format_op(*op)
        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == 2 and op.op in ('DW_OP_entry_value', 'DW_OP_GNU_entry_value'):
                return 'Double-click for details'

# TODO: a dialog with a table and a close button should be reused elsewhere
# TODO: copy
# TODO: reg names, hex, prefix toggles
# TODO: low level mode that shows bytes?
# This is a dialog for browsing DWARF expressions, not entering Python expressions
class ExpressionDlg(QDialog):
    def __init__(self, win, title, e, f):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.setWindowTitle(title)
        self.resize(500, 400)

        entries = self.entries = QTableView()
        entries.setModel(ExpressionModel(e, f))
        header = entries.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        entries.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        entries.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        entries.doubleClicked.connect(self.on_line_dclick)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        buttons.rejected.connect(self.reject)

        ly = QVBoxLayout()
        ly.addWidget(entries)
        ly.addWidget(buttons)
        self.setLayout(ly)

    def on_line_dclick(self, index):
        op = index.internalPointer()
        if op.op in ('DW_OP_entry_value', 'DW_OP_GNU_entry_value'):
            title = f'Nested expression in {op.op} at 0x{op.offset:x}'
            ExpressionDlg(self, title, op.args[0], self.formatter).exec()

