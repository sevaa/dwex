from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt, QAbstractTableModel

HEADERS = ('#', 'Offset', 'Operation')

def op_has_nested_expression(op):
    return op.op in ('DW_OP_entry_value', 'DW_OP_GNU_entry_value')

# TODO: low level maybe
# Spell out args?
# Opcode tooltips?
class ExpressionTableModel(QAbstractTableModel):
    # Expr is a list of operation objects
    # Used also for expressions in the details pane
    # Assumes double-clicks are caught by the table owner, elsewhere
    # But presents "double-click for details
    # The index data item is an operation namedtuple from DWARFExprParser
    def __init__(self, expr, formatter):
        super().__init__()
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
            if col == 2 and op_has_nested_expression(op):
                return 'Double-click for details'

# TODO: a dialog with a table and a close button should be reused elsewhere
# TODO: copy
# TODO: reg names, hex, prefix toggles
# TODO: low level mode that shows bytes?
# This is a dialog for browsing DWARF expressions, not entering Python expressions
class ExpressionDlg(QDialog):
    def __init__(self, win, title, e, f):
        super().__init__(win, Qt.WindowType.Dialog)
        self.setWindowTitle(title)
        self.resize(500, 400)

        entries = self.entries = QTableView()
        entries.setModel(ExpressionTableModel(e, f))
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
        if op_has_nested_expression(op):
            title = f'Nested expression in {op.op} at 0x{op.offset:x}'
            ExpressionDlg(self, title, op.args[0], self.formatter).exec()

