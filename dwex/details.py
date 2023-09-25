from PyQt6.QtCore import Qt, QAbstractTableModel
from PyQt6.QtGui import QFont

_fixed_font = None

class GenericTableModel(QAbstractTableModel):
    def __init__(self, headers, values, warning = None, get_tooltip = None):
        QAbstractTableModel.__init__(self)
        self.headers = headers
        self.values = tuple(values)
        self.warning = warning
        self.get_tooltip = get_tooltip

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]

    def rowCount(self, parent):
        return len(self.values)

    def columnCount(self, parent):
        return len(self.headers)

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            return self.values[index.row()][index.column()]
        elif role == Qt.ItemDataRole.ToolTipRole:
            if self.get_tooltip:
                return self.get_tooltip(index.row(), index.column())

class FixedWidthTableModel(GenericTableModel):
    def __init__(self, headers, values):
        GenericTableModel.__init__(self, headers, values)

    def data(self, index, role):
        if role == Qt.ItemDataRole.FontRole:
            global _fixed_font
            if not _fixed_font:
                _fixed_font = QFont("Monospace")
                _fixed_font.setStyleHint(QFont.StyleHint.TypeWriter)
            return _fixed_font
        else:
            return GenericTableModel.data(self, index, role)