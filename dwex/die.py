from bisect import bisect_right
from PyQt6.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QBrush, QFont
from elftools.dwarf.locationlists import LocationParser, LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.descriptions import _DESCR_DW_LANG, _DESCR_DW_ATE, _DESCR_DW_ACCESS, _DESCR_DW_INL
from elftools.common.exceptions import ELFParseError
from elftools.dwarf.ranges import BaseAddressEntry as RangeBaseAddressEntry, RangeEntry

from dwex.exprutil import ExprFormatter
from .dwarfone import DWARFExprParserV1
from .dwarfutil import *

MAX_INLINE_BYTEARRAY_LEN = 32

def is_long_blob(attr):
    val = attr.value
    return ((isinstance(val, bytes) and attr.form not in ('DW_FORM_strp', 'DW_FORM_string')) or is_int_list(val)) and len(val) > MAX_INLINE_BYTEARRAY_LEN

#------------------------------------------------
# DIE formatter
#------------------------------------------------

_blue_brush = QBrush(Qt.GlobalColor.blue)
_ltgrey_brush = QBrush(Qt.GlobalColor.lightGray)
_fixed_font = None

_ll_headers = ("Attribute", "Offset", "Form", "Raw", "Value")
_noll_headers = ("Attribute", "Form", "Value")
_meta_desc = ('DIE offset', 'DIE size', 'Abbrev code', 'Has children') # Anything else?
_meta_count = 4 # Extra rows if low level detail showing is set

class DIETableModel(QAbstractTableModel):
    def __init__(self, die, prefix, lowlevel, hex, regnames):
        QAbstractTableModel.__init__(self)
        self.prefix = prefix
        self.lowlevel = lowlevel
        self.hex = hex
        self.regnames = regnames
        self.die = die
        self.attributes = die.attributes
        self.keys = list(die.attributes.keys())
        self.headers = _ll_headers if self.lowlevel else _noll_headers
        self.meta_count = _meta_count if lowlevel else 0
        self.expr_formatter = ExprFormatter(regnames, prefix, die.dwarfinfo.config.machine_arch, die.cu['version'], hex)

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]

    def rowCount(self, parent):
        return len(self.keys) + self.meta_count

    def columnCount(self, parent):
        return len(self.headers)

    def parse_location(self, attr):
        di = self.die.dwarfinfo
        if di._locparser is None:
            di._locparser = LocationParser(di.location_lists())
        return di._locparser.parse_from_attribute(attr, self.die.cu['version'], die = self.die)

    def data(self, index, role):
        row = index.row()
        return self.attr_data(index, role) if row >= self.meta_count else self.meta_data(index, role)

    def attr_data(self, index, role):
        irow = index.row()
        meta_count = self.meta_count
        self_keys_len = len(self.keys)
        self_die_keys_len = len(self.die.attributes.keys())
        row = index.row() - self.meta_count
        key = self.keys[row]
        attr = self.attributes[key]
        if role == Qt.ItemDataRole.DisplayRole:
            col = index.column()
            if col == 0:
                # Unknown keys come across as ints
                return key if self.prefix or not str(key).startswith('DW_AT_') else key[6:]
            elif col == 1:
                return hex(attr.offset) if self.lowlevel else self.format_form(attr.form)
            elif col == 2:
                return self.format_form(attr.form) if self.lowlevel else self.format_value(attr)
            elif col == 3:
                return self.format_raw(attr) if self.lowlevel else self.format_value(attr)
            elif col == 4:
                return self.format_value(attr)
        elif role == Qt.ItemDataRole.ToolTipRole:
            if attr.form in ('DW_FORM_ref', 'DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr'):
                return "Double-click to follow"
            elif attr.form in ('DW_FORM_ref_sig8', 'DW_FORM_ref_sup4', 'DW_FORM_ref_sup8'):
                return "Unsupported reference format"
            elif is_long_blob(attr):
                return "Click to see it all"
        elif role == Qt.ItemDataRole.ForegroundRole:
            if attr.form in ('DW_FORM_ref', 'DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr'):
                return _blue_brush
        elif role == Qt.ItemDataRole.BackgroundRole:
            if self.lowlevel and index.column() == 3 and attr.raw_value == attr.value:
                return _ltgrey_brush                

    # Data for the metadata lines - ones that are not attributes
    def meta_data(self, index, role):
        row = index.row()
        if role == Qt.ItemDataRole.DisplayRole:
            col = index.column()
            if col == 0:
                return _meta_desc[row]
            elif col == (4 if self.lowlevel else 2):
                if row == 0:
                    return hex(self.die.offset)
                if row == 1: # Should this be always hex? Not sure...
                    return hex(self.die.size) if self.hex else str(self.die.size)
                elif row == 2: # Hex makes no sense here
                    return str(self.die.abbrev_code)                    
                elif row == 3:
                    return str(self.die.has_children)
        elif role == Qt.ItemDataRole.BackgroundRole:
            return _ltgrey_brush

    # End of Qt callbacks

    # Expr is an expression blob
    # Returns a list of strings for ops
    # Format: op arg, arg...
    def dump_expr(self, expr):
        if self.die.cu._exprparser is None:
            self.die.cu._exprparser = DWARFExprParser(self.die.cu.structs) if self.die.cu['version'] > 1 else DWARFExprParserV1(self.die.cu.structs)

        # Challenge: for nested expressions, args is a list with a list of commands
        # For those, the format is: op {op arg, arg; op arg, arg}
        # Can't just check for iterable, str is iterable too
        return [self.expr_formatter.format_op(*op) for op in self.die.cu._exprparser.parse_expr(expr)]

    # Big DIE attribute value interpreter
    def format_value(self, attr):
        try:
            die = self.die
            cu = self.die.cu
            header = self.die.cu.header
            dwarf_version = self.die.cu.header.version                               

            key = attr.name
            val = attr.value
            form = attr.form
            if form == 'DW_FORM_addr' and isinstance(val, int):
                return hex(val)
            elif form == 'DW_FORM_flag_present':
                return 'True'
            elif form in ('DW_FORM_ref0', 'DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8', 'DW_FORM_ref_addr'):
                return "Ref: 0x%x" % val # There are several other reference forms in the spec
            elif form == 'DW_FORM_flag':
                return str(bool(val))
            elif LocationParser.attribute_has_location(attr, self.die.cu['version']):
                ll = self.parse_location(attr)
                if isinstance(ll, LocationExpr):
                    return '; '.join(self.dump_expr(ll.loc_expr))
                else:
                    return "Loc list: 0x%x" % attr.value
            elif key == 'DW_AT_language':
                return "%d %s" % (val, _DESCR_DW_LANG[val]) if val in _DESCR_DW_LANG else val
            elif key == 'DW_AT_encoding':
                return "%d %s" % (val, _DESCR_DW_ATE[val]) if val in _DESCR_DW_ATE else val
            elif key == 'DW_AT_accessibility':
                return "%d %s" % (val, _DESCR_DW_ACCESS[val]) if val in _DESCR_DW_ACCESS else val
            elif key == 'DW_AT_inline':
                return "%d %s" % (val, _DESCR_DW_INL[val]) if val in _DESCR_DW_INL else val
            elif key in ('DW_AT_decl_file', 'DW_AT_call_file'):
                cu = self.die.cu
                if cu._lineprogram is None:
                    cu._lineprogram = self.die.dwarfinfo.line_program_for_CU(cu)
                if cu._lineprogram:
                    if cu._lineprogram.header.version >= 5:
                        filename = cu._lineprogram.header.file_entry[val].name.decode('utf-8', errors='ignore') if cu._lineprogram and val >= 0 and val < len(cu._lineprogram.header.file_entry) else '(N/A)'
                    else:
                        if val == 0:
                            filename = safe_DIE_name(cu.get_top_DIE(), 'N/A')
                        else:
                            filename = cu._lineprogram.header.file_entry[val-1].name.decode('utf-8', errors='ignore') if cu._lineprogram and val > 0 and val <= len(cu._lineprogram.header.file_entry) else '(N/A)'
                    return "%d: %s" % (val,  filename)
                else: # Lineprogram not found in the top DIE - how's that possible?
                    return "%d (no lineprogram found)" % (val,)
            elif key == 'DW_AT_stmt_list':
                return 'LNP at 0x%x' % val
            elif key in ('DW_AT_upper_bound', 'DW_AT_lower_bound') and is_block(form):
                return '; '.join(self.dump_expr(val))
            elif isinstance(val, bytes):
                if form in ('DW_FORM_strp', 'DW_FORM_string', 'DW_FORM_line_strp', 'DW_FORM_strp_sup',
                    'DW_FORM_strx', 'DW_FORM_strx1', 'DW_FORM_strx2', 'DW_FORM_strx3', 'DW_FORM_strx4'):
                    return val.decode('utf-8', errors='ignore')
                elif val == b'': # What's a good value for a blank blob?
                    return '[]'
                elif len(val) > MAX_INLINE_BYTEARRAY_LEN:
                    return ' '.join("%02x" % b for b in val[0:MAX_INLINE_BYTEARRAY_LEN]) + ("...(%s bytes)" % (('0x%x' if self.hex else '%d') % len(val)))
                else:
                    return ' '.join("%02x" % b for b in val) # Something like "01 ff 33 55"
            elif isinstance(val, list): # block1 comes across as this
                if val == []:
                    return '[]'
                elif isinstance(val[0], int): # Assuming it's a byte array diguised as int array
                    if len(val) > MAX_INLINE_BYTEARRAY_LEN:
                        return ' '.join("%02x" % b for b in val[0:MAX_INLINE_BYTEARRAY_LEN]) + ("...(%s bytes)" % (('0x%x' if self.hex else '%d') % len(val)))
                    else:
                        return ' '.join("%02x" % b for b in val)
                else: # List of something else
                    return str(val)
            else:
                return hex(val) if self.hex and isinstance(val, int) else str(val)
        except ELFParseError as exc:
            from .__main__ import version
            from .crash import report_crash
            from inspect import currentframe
            tb = exc.__traceback__
            report_crash(exc, tb, version, currentframe(), ctxt = {'attr': attr, 'die':die, 'cu_header':header, 'dwarf_version':dwarf_version})
            return "(parse error - please report at github.com/sevaa/dwex)"

    def format_form(self, form):
        return form if self.prefix or not str(form).startswith('DW_FORM_') else form[8:]

    def format_raw(self, attr):
        val = attr.raw_value
        if val == attr.value:
            return "(same)"
        elif isinstance(val, int):
            return hex(val) if self.hex else str(val)
        elif isinstance(val, bytes) or (isinstance(val, list) and len(val) > 0 and isinstance(val[0], int)):
            return ' '.join("%02x" % b for b in val) if len(val) > 0 else '[]'
        else:
            return str(val)

    def display_DIE(self, die):
        rows_was = len(self.keys) + self.meta_count
        self.die = die
        self.attributes = die.attributes
        self.keys = list(die.attributes.keys())
        # Should not be ever possible, but this code is here
        self.expr_formatter.set_arch(die.dwarfinfo.config.machine_arch)
        self.expr_formatter.dwarf_version = die.cu['version']
        rows_now = self.meta_count + len(self.keys)
        if rows_was < rows_now:
            self.rowsInserted.emit(QModelIndex(), rows_was, rows_now-1)
        elif rows_was > rows_now:
            self.rowsRemoved.emit(QModelIndex(), rows_now, rows_was-1)
        self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(rows_now - 1, len(self.headers)-1))

    def set_prefix(self, prefix):
        if prefix != self.prefix:
            self.prefix = prefix
            self.expr_formatter.prefix = prefix
            self.refresh_values()

    # Index is the current selected index
    # Returns the new selected index, if there was one
    def set_lowlevel(self, lowlevel, index):
        if lowlevel != self.lowlevel:
            self.lowlevel = lowlevel
            self.headers = _ll_headers if self.lowlevel else _noll_headers
            new_index = None
            if lowlevel:
                self.beginInsertColumns(QModelIndex(), 2, 3)
                self.endInsertColumns()
                self.meta_count = _meta_count
                self.rowsInserted.emit(QModelIndex(), 0, self.meta_count - 1)
                if index.isValid(): # Shift the selection two down
                    new_index = self.createIndex(index.row() + self.meta_count, 0)
            else:
                meta_count_was = self.meta_count # Allows for meta_count to be dependent on DIE
                self.beginRemoveColumns(QModelIndex(), 2, 3)
                self.endRemoveColumns()
                self.meta_count = 0
                self.rowsRemoved.emit(QModelIndex(), 0, meta_count_was - 1)
                if index.isValid() and index.row() >= meta_count_was: # Shift the selection down
                    new_index = self.createIndex(index.row() - meta_count_was, 0)
                else:
                    new_index = QModelIndex() # Select none
        return new_index

    # Force a reload of values on the whole table without row/column count change
    def refresh_values(self):
        self.dataChanged.emit(self.createIndex(0, 0), self.createIndex(self.meta_count + len(self.keys)-1, len(self.headers)-1))

    def set_hex(self, hex):
        if hex != self.hex:
            self.hex = hex
            self.refresh_values()

    def set_regnames(self, regnames):
        if regnames != self.regnames:
            self.regnames = regnames
            self.expr_formatter.regnames = regnames
            self.refresh_values()

    # Returns a table model for the attribute details table
    # For attributes that refer to larger data structures (ranges, locations), makes sense to spell it out into a table
    # Row is metadata unaware
    def get_attribute_details(self, index):
        row = index.row()
        if row >= self.meta_count:
            row -= self.meta_count
            key = self.keys[row]
            attr = self.attributes[key]
            form = attr.form
            if key == "DW_AT_ranges":
                di = self.die.dwarfinfo
                if not di._ranges:
                    di._ranges = di.range_lists()
                if not di._ranges: # Absent in the DWARF file
                    return None
                ranges = di._ranges.get_range_list_at_offset(attr.value, cu = self.die.cu)
                top_die = self.die.cu.get_top_DIE() 
                warn = None
                lines = []                
                if len(ranges):
                    cu_base = 0
                    # Do we need the base address? We might not.
                    has_relative_entries = next((r for r in ranges if isinstance(r, RangeEntry) and not r.is_absolute), False)
                    if has_relative_entries and not isinstance(ranges[0], RangeBaseAddressEntry):
                        try:
                            cu_base = get_cu_base(self.die)
                        except NoBaseError:
                            warn = "Base address not found, assuming 0"

                    # TODO: low level view?
                    for r in ranges:
                        if isinstance(r, RangeEntry):
                            base = 0 if r.is_absolute else cu_base
                            lines.append((hex(base + r.begin_offset), hex(base + r.end_offset)))
                        else:
                            cu_base = r.base_address
                else:
                    warn = "Empty range list"
                return GenericTableModel(("Start offset", "End offset"), lines, warn)
            elif LocationParser.attribute_has_location(attr, self.die.cu['version']):
                # Expression is a list of ints
                ll = self.parse_location(attr)
                if isinstance(ll, LocationExpr):
                    return GenericTableModel(("Command",), ((cmd,) for cmd in self.dump_expr(ll.loc_expr)))
                else:
                    cu_base = get_cu_base(self.die)
                    values = list()
                    if self.lowlevel:
                        headers = ("Start offset", "End offset", "Expr bytes", "Expression")
                        for l in ll:
                            if 'base_address' in l._fields:
                                cu_base = l.base_address
                                values.append(("(base)", hex(cu_base), '', ''))
                            else:
                                try: # Catching #1609
                                    expr_dump = '; '.join(self.dump_expr(l.loc_expr))
                                except KeyError as exc:
                                    expr_dump = "<unrecognized expression>"
                                    from .__main__ import version
                                    from .crash import report_crash
                                    from inspect import currentframe
                                    report_crash(exc, exc.__traceback__, version, currentframe())
                                values.append((hex(cu_base + l.begin_offset),
                                    hex(cu_base + l.end_offset),
                                    ' '.join("%02x" % b for b in l.loc_expr),
                                    expr_dump))
                    else: # Not low level
                        headers = ("Start offset", "End offset", "Expression")
                        for l in ll:
                            if 'base_address' in l._fields:
                                cu_base = l.base_address
                            else:
                                try: # Catching #1609
                                    expr_dump = '; '.join(self.dump_expr(l.loc_expr))
                                except KeyError as exc:
                                    expr_dump = "<unrecognized expression>"
                                    from .__main__ import version
                                    from .crash import report_crash
                                    from inspect import currentframe
                                    report_crash(exc, exc.__traceback__, version, currentframe())
                                values.append((hex(cu_base + l.begin_offset),
                                    hex(cu_base + l.end_offset),
                                    expr_dump))

                    return GenericTableModel(headers, values)
            elif key == 'DW_AT_stmt_list':
                if self.die.cu._lineprogram is None:
                    self.die.cu._lineprogram = self.die.dwarfinfo.line_program_for_CU(self.die.cu)
                lpe = self.die.cu._lineprogram.get_entries()
                files = self.die.cu._lineprogram.header.file_entry
                ver5 = self.die.cu._lineprogram.header.version >= 5
                def_file = safe_DIE_name(self.die.cu.get_top_DIE(), 'N/A')
                def format_state(state):
                    filename = 'N/A'
                    if ver5:
                        if state.file >= 0 and state.file < len(files):
                            filename = files[state.file].name.decode('utf-8', errors='ignore')
                    else:
                        if state.file == 0:
                            filename = def_file
                        elif state.file >= 1 and state.file <= len(files):
                            filename = files[state.file-1].name.decode('utf-8', errors='ignore')
                    return (hex(state.address),
                        filename,
                        state.line,
                        'Y' if state.is_stmt  else '',
                        'Y' if state.basic_block else '',
                        'Y' if state.end_sequence else '',
                        'Y' if state.prologue_end else '',
                        'Y' if state.epilogue_begin else '')
                states = [format_state(e.state) for e in lpe if e.state]
                # TODO: low level flavor with extra details
                # TODO: commands vs states
                return GenericTableModel(('Address', 'File', 'Line', 'Stmt', 'Basic block', 'End seq', 'End prologue', 'Begin epilogue'), states)
            elif key in ('DW_AT_upper_bound', 'DW_AT_lower_bound') and is_block(form):
                return GenericTableModel(("Command",), [(o,) for o in self.dump_expr(attr.value)])
            elif is_long_blob(attr):
                val = attr.value
                def format_line(off):
                    offs = ("0x%x" if self.hex else "%d") % off
                    return (offs, ' '.join("%02x" % b for b in val[off:off+MAX_INLINE_BYTEARRAY_LEN]))
                lines = [format_line(off) for off in range(0, len(val), MAX_INLINE_BYTEARRAY_LEN)]
                return FixedWidthTableModel(('Offset (%s)' % ('hex' if self.hex else 'dec'), 'Bytes'), lines)
        return None

    # Returns (cu, die_offset) or None if not a navigable
    def ref_target(self, index):
        try:  # Any chance for "not found"? Probably bug #1450, #1450
            row = index.row()
            if row >= self.meta_count:
                attr_name = self.keys[row - self.meta_count]
                attr = self.attributes[attr_name]
                val = attr.value
                form = attr.form
                if form in ('DW_FORM_ref1', 'DW_FORM_ref2', 'DW_FORM_ref4', 'DW_FORM_ref8'):
                    return (self.die.cu, attr.value + self.die.cu.cu_offset)
                elif form in ('DW_FORM_ref_addr', 'DW_FORM_ref'):
                    cualen = len(self.die.cu.dwarfinfo._unsorted_CUs)
                    i = bisect_right(self.die.cu.dwarfinfo._CU_offsets, val) - 1
                    cu = self.die.cu.dwarfinfo._unsorted_CUs[i]
                    return (cu, attr.value)
        except IndexError as exc:
            from .__main__ import version
            from .crash import report_crash
            from inspect import currentframe
            tb = exc.__traceback__
            report_crash(exc, tb, version, currentframe())
            return None

class GenericTableModel(QAbstractTableModel):
    def __init__(self, headers, values, warning = None):
        QAbstractTableModel.__init__(self)
        self.headers = headers
        self.values = tuple(values)
        self.warning = warning

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

