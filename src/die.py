from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
from PyQt5.QtGui import QBrush

#------------------------------------------------
# DIE formatter
#------------------------------------------------

_blue_brush = QBrush(Qt.GlobalColor.blue)

class DIETableModel(QAbstractTableModel):
    def __init__(self, die, prefix):
        QAbstractTableModel.__init__(self)
        self.prefix = prefix
        self.die = die
        self.attributes = die.attributes
        self.keys = list(die.attributes.keys())

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.DisplayRole:
            return ("Attribute", "Form", "Value")[section]

    def rowCount(self, parent):
        return len(self.keys)

    def columnCount(self, parent):
        return 3

    def format_value(self, attr):
        val = attr.value
        form = attr.form
        if isinstance(val, bytes):
            return val.decode('utf-8')
        elif form == 'DW_FORM_addr' and isinstance(val, int):
            return "0x%X" % val
        elif form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'):
            return "Ref: 0x%X" % val
        else:
            return str(val)

    def data(self, index, role):
        row = index.row()
        key = self.keys[row]
        attr = self.attributes[key]
        if role == Qt.DisplayRole:
            col = index.column()
            if col == 0:
                return key[0 if self.prefix else 6:]
            elif col == 1:
                return attr.form[0 if self.prefix else 8:]
            elif col == 2:
                return self.format_value(attr)
        elif role == Qt.ToolTipRole:
            if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'):
                return "Double-click to follow"
            elif attr.form in ('DW_FORM_ref_addr', 'DW_FORM_ref_sig8', 'DW_FORM_ref_sup4', 'DW_FORM_ref_sup8'):
                return "Unsupported reference format"
        elif role == Qt.ForegroundRole:
            if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'):
                return _blue_brush

    def display_DIE(self, die):
        rows_was = len(self.keys)
        self.die = die
        self.attributes = die.attributes
        self.keys = list(die.attributes.keys())
        rows_now = len(self.keys)
        if rows_was < rows_now:
            self.rowsInserted.emit(QModelIndex(), rows_was, rows_now-1)
        elif rows_was > rows_now:
            self.rowsRemoved.emit(QModelIndex(), rows_now, rows_was-1)
        self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(rows_now-1, 3))

    def set_prefix(self, prefix):
        if prefix != self.prefix:
            self.prefix = prefix
            self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(len(self.keys)-1, 0))

    # For attributes that refer to larger data structures, spell it out into a table
    def get_attribute_details(self, row):
        key = self.keys[row]
        attr = self.attributes[key]
        form = attr.form
        if key == "DW_AT_ranges" and form == 'DW_FORM_sec_offset':
            di = self.die.dwarfinfo
            if not di._ranges:
                di._ranges = di.range_lists()
            if not di._ranges: # Absent in the DWARF file
                return None
            ranges = di._ranges.get_range_list_at_offset(attr.value)
            return GenericTableModel(("Start offset", "End offset"), (("0x%X" % r.begin_offset, "0x%X" % r.end_offset) for r in ranges))
        return None

    # Returns (cu, die_offset) or None if not a navigable
    def ref_target(self, index):
        attr = self.attributes[self.keys[index.row()]]
        if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'):
            return (self.die.cu, attr.value + self.die.cu.cu_offset)
        return None


class GenericTableModel(QAbstractTableModel):
    def __init__(self, headers, values):
        QAbstractTableModel.__init__(self)
        self.headers = headers
        self.values = tuple(values)

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]

    def rowCount(self, parent):
        return len(self.values)

    def columnCount(self, parent):
        return len(self.headers)

    def data(self, index, role):
        if role == Qt.DisplayRole:
            return self.values[index.row()][index.column()]