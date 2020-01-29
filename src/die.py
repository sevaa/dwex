from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
from PyQt5.QtGui import QBrush
from elftools.dwarf.locationlists import LocationParser, LocationExpr
from elftools.dwarf.dwarf_expr import GenericExprDumper, DW_OP_opcode2name

#------------------------------------------------
# DIE formatter
#------------------------------------------------

_blue_brush = QBrush(Qt.GlobalColor.blue)

ll_headers = ("Attribute", "Form", "Raw", "Value")
headers = ("Attribute", "Form", "Value")

# Format: op arg, arg...
class ExprDumper(GenericExprDumper):
    def __init__(self, structs, prefix):
        GenericExprDumper.__init__(self, structs)
        self.prefix = prefix

    def set_prefix(self, prefix):
        self.prefix = prefix

    def _dump_to_string(self, opcode, opcode_name, args):
        # Challenge: for nested expressions, args is a list with a list of commands
        # For those, the format is: op {op arg, arg; op arg, arg}
        if opcode_name.startswith('DW_OP_') and not self.prefix:
            opcode_name = opcode_name[6:]

        if args:
            args = [str(s) if isinstance(s, str) or isinstance(s, int) else '{' + '; '.join(s) + '}' for s in args]
            args = ', '.join(args)
            return opcode_name + ' ' + args
        else:
            return opcode_name

# TODO: cache expr dumper on CU level, not here
class DIETableModel(QAbstractTableModel):
    def __init__(self, die, prefix, lowlevel, hex):
        QAbstractTableModel.__init__(self)
        self.prefix = prefix
        self.lowlevel = lowlevel
        self.hex = hex
        self.die = die
        self.attributes = die.attributes
        self.keys = list(die.attributes.keys())
        self._exprdumper = None

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.DisplayRole:
            return (ll_headers if self.lowlevel else headers)[section]

    def rowCount(self, parent):
        return len(self.keys)

    def columnCount(self, parent):
        return 4 if self.lowlevel else 3

    def parse_location(self, attr):
        di = self.die.dwarfinfo
        if di._locparser is None:
            di._locparser = LocationParser(di.location_lists())
        if self._exprdumper is None:
            self._exprdumper = ExprDumper(self.die.cu.structs, self.prefix)
        return di._locparser.parse_from_attribute(attr, self.die.cu['version'])

    def data(self, index, role):
        row = index.row()
        key = self.keys[row]
        attr = self.attributes[key]
        if role == Qt.DisplayRole:
            col = index.column()
            if col == 0:
                return key if self.prefix or not key.startswith('DW_AT_')  else key[6:]
            elif col == 1:
                return attr.form if self.prefix or not attr.form.startswith('DW_FORM_') else attr.form[8:]
            elif col == 2:
                return self.format_raw(attr) if self.lowlevel else self.format_value(attr)
            elif col == 3:
                return self.format_value(attr)
        elif role == Qt.ToolTipRole:
            if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr'):
                return "Double-click to follow"
            elif attr.form in ('DW_FORM_ref_sig8', 'DW_FORM_ref_sup4', 'DW_FORM_ref_sup8'):
                return "Unsupported reference format"
        elif role == Qt.ForegroundRole:
            if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr'):
                return _blue_brush

    # End of Qt callbacks

    # Big DIE attribute value interpreter
    def format_value(self, attr):
        val = attr.value
        form = attr.form
        if isinstance(val, bytes):
            return val.decode('utf-8')
        elif form == 'DW_FORM_addr' and isinstance(val, int):
            return hex(val)
        elif form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr'):
            return "Ref: 0x%X" % val # There are several other reference forms in the spec
        elif LocationParser.attribute_has_location(attr, self.die.cu['version']):
            ll = self.parse_location(attr)
            if isinstance(ll, LocationExpr):
                return '; '.join(self._exprdumper.dump(ll.loc_expr))
            else:
                return "Loc list: 0x%X" % attr.value
        else:
            return hex(val) if isinstance(val, int) and self.hex else str(attr.raw_value)

    def format_raw(self, attr):
        return hex(attr.raw_value) if isinstance(attr.raw_value, int) and self.hex else str(attr.raw_value)

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
            self.dataChanged.emit(self.createIndex(0, 2), self.createIndex(len(self.keys)-1, 3))
            if self._exprdumper:
                self._exprdumper.set_prefix(prefix)

    def set_lowlevel(self, lowlevel):
        if lowlevel != self.lowlevel:
            self.lowlevel = lowlevel
            if lowlevel:
                self.beginInsertColumns(QModelIndex(), 2, 2)
                self.endInsertColumns()
            else:
                self.beginRemoveColumns(QModelIndex(), 2, 2)
                self.endRemoveColumns()

    def set_hex(self, hex):
        if hex != self.hex:
            self.hex = hex
            self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(len(self.keys)-1, 0))

    # Returns a table model for the attribute details
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
            return GenericTableModel(("Start offset", "End offset"), ((hex(r.begin_offset), hex(r.end_offset)) for r in ranges))
        elif LocationParser.attribute_has_location(attr, self.die.cu['version']):
            ll = self.parse_location(attr)
            if isinstance(ll, LocationExpr):
                return GenericTableModel(("Command",), ((cmd,) for cmd in self._exprdumper.dump(ll.loc_expr)))
            else:
                return GenericTableModel(("Start offset", "End offset", "Expression"),
                    ((hex(l.begin_offset), hex(l.end_offset), '; '.join(self._exprdumper.dump(l.loc_expr))) for l in ll))
        return None

    # Returns (cu, die_offset) or None if not a navigable
    def ref_target(self, index):
        attr = self.attributes[self.keys[index.row()]]
        if attr.form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'):
            return (self.die.cu, attr.value + self.die.cu.cu_offset)
        elif attr.form == 'DW_FORM_ref_addr':
            prev_cu = None
            for cu in self.die.dwarfinfo._CUs: # Don't reparse CUs, reuse cached ones
                if prev_cu is None:
                    prev_cu = cu
                elif cu.cu_offset > attr.value:
                    return (prev_cu, attr.value)
                else:
                    prev_cu = cu
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