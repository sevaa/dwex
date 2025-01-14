from PyQt6.QtCore import Qt, QAbstractTableModel
from .fx import fixed_font

class GenericTableModel(QAbstractTableModel):
    """ The index internal object is the row
        The column count is driven by headers - OK to piggyback extra data in values' rows
    """
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
    
    def index(self, row, col, parent):
        return self.createIndex(row, col, self.values[row])

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            return index.internalPointer()[index.column()]
        elif role == Qt.ItemDataRole.ToolTipRole:
            if self.get_tooltip:
                return self.get_tooltip(index.row(), index.column(), index.internalPointer())

class FixedWidthTableModel(GenericTableModel):
    def __init__(self, headers, values):
        super().__init__(headers, values)

    def data(self, index, role):
        if role == Qt.ItemDataRole.FontRole:
            return fixed_font()
        else:
            return super().data(index, role)