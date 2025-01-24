from PyQt6.QtCore import Qt, QAbstractTableModel
from PyQt6.QtWidgets import *

from elftools.dwarf.callframe import FDE, RegisterRule, ZERO
from elftools.dwarf.dwarf_expr import DWARFExprParser

from .exprdlg import ExpressionDlg
from .fx import bold_font
from .locals import LoadedModuleDlgBase
from .exprutil import _REG_NAME_MAP, ExprFormatter, format_offset

rheaders = ('Start address', 'End address', 'Length')
eheaders = ('Type', 'CIE offset', 'Start address', 'End address', 'Length')

# TODO: more fields in entries mode? Version, augmentation, etc? Or a properties window?
# TODO: dump raw instructions in details?
class EntriesModel(QAbstractTableModel):
    def __init__(self, cfi, fdes_only, hex):
        QAbstractTableModel.__init__(self)
        self.fdes_only = fdes_only
        self.headers = rheaders if fdes_only else eheaders
        self.hex = hex
        if fdes_only:
            self.entries = [e for e in cfi if isinstance(e, FDE)]
            self.entries.sort(key=lambda e: e.header.initial_location)
        else:
            self.entries = cfi

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.headers[section]
        
    def rowCount(self, parent):
        return len(self.entries)

    def columnCount(self, parent):
        return len(self.headers)
    
    def index(self, row, col, parent):
        return self.createIndex(row, col, self.entries[row])
    
    def data(self, index, role):
        col = index.column()
        entry = index.internalPointer()
        header = entry.header if not isinstance(entry, ZERO) else None
        is_fde = isinstance(entry, FDE)
        if role == Qt.ItemDataRole.DisplayRole:
            # In entries mode, the first two columns are for all lines, the rest of columns is the FDE display
            if not self.fdes_only:
                if col == 0:
                    return ('FDE' if is_fde else 'CIE') if header else 'ZERO'
                if col == 1:
                    return (hex(entry.cie.offset if is_fde else entry.offset)) if header else ''
                    # CIE_offset in FDE header is relative in EH section, absolute in debug_frames
                else:
                    col -= 2
            if is_fde:
                if col == 0:
                    return hex(header.initial_location)
                elif col == 1:
                    return hex(header.initial_location + header.address_range - 1)
                elif col == 2:
                    return hex(header.address_range) if self.hex else str(header.address_range)
        elif role == Qt.ItemDataRole.FontRole:
            if not self.fdes_only and is_fde:
                return bold_font()

class DecodedEntryModel(QAbstractTableModel):
    def __init__(self, entry, regnamelist, p, f):
        QAbstractTableModel.__init__(self)
        self.table = entry.get_decoded() # Anything else from the entry?
        self.regnamelist = regnamelist
        self.parser = p
        self.formatter = f
        # TODO: sort them?

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if section == 0:
                return "Address"
            elif section == 1:
                return 'CFA'
            else:
                regno = self.table.reg_order[section-2]
                return self.regname(regno)
        
    def rowCount(self, parent):
        return len(self.table.table)

    def columnCount(self, parent):
        return len(self.table.reg_order) + 2
    
    def index(self, row, col, parent):
        return self.createIndex(row, col, self.table.table[row])
    
    def data(self, index, role):
        # Helper...
        def format_rule_expr(expr):
            if not hasattr(rule, 'expr'): # Implementation detail: rule is an open ended object
                rule.expr = self.parser.parse_expr(rule.arg)
            expr = rule.expr
            if len(expr) > 3:
                return '; '.join(self.formatter.format_op(*op) for op in expr[:3]) + f';...{len(expr)-3} more'
            else:
                return '; '.join(self.formatter.format_op(*op) for op in expr)

        col = index.column()
        line = index.internalPointer()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return hex(line['pc'])
            elif col == 1:
                rule = line['cfa']
                if rule.expr is not None:
                    return '(expr)' # TODO!!!
                elif rule.reg is not None:
                    return self.regname(rule.reg) + format_offset(rule.offset)
                else:
                    return '(unclear)' # TODO: catch? #1743
            else:
                regno = self.table.reg_order[col-2]
                if regno in line:
                    rule = line[regno]
                    type = rule.type
                    if type == 'ARCHITECTURAL':
                        return '(arch)'
                    elif type == 'EXPRESSION':
                        return f'[{format_rule_expr(rule)}]'
                    elif type == 'OFFSET':
                        return "[CFA%s]" % (format_offset(rule.arg),)
                    elif type == 'REGISTER':
                        return self.regname(rule.arg)
                    elif type == 'SAME_VALUE':
                        return '(same)'
                    elif type == 'UNDEFINED':
                        return '(undef)'
                    elif type == 'VAL_EXPRESSION':
                        return format_rule_expr(rule)
                    elif type == 'VAL_OFFSET':
                        return "CFA%s" % (format_offset(rule.arg),)
        elif role == Qt.ItemDataRole.ToolTipRole:
            if col >= 2:
                regno = self.table.reg_order[col-2]
                if regno in line:
                    rule = line[regno]
                    if rule.type in ('EXPRESSION', 'VAL_EXPRESSION'):
                        return 'Double-click for details'
                
    def regname(self, regno):
        return self.regnamelist[regno] if self.regnamelist else "r%d" % (regno,)
    
    def get_expr_rule(self, index):
        col = index.column()
        if col >= 2:
            regno = self.table.reg_order[col-2]
            rule = index.internalPointer()[regno]
            if rule.type in ('VAL_EXPRESSION', 'EXPRESSION'):
                if not hasattr(rule, 'expr'): # Implementation detail: rule is an open ended object
                    rule.expr = self.parser.parse_expr(rule.arg)
                return rule
            
    def get_regname_by_index(self, index):
        col = index.column()
        if col >= 2:
            regno = self.table.reg_order[col-2]
            return self.regname(regno)


#########################################################

# Reused for unwind info - sans the top buttons
class FramesUIDlg(LoadedModuleDlgBase):
    def __init__(self, win):
        LoadedModuleDlgBase.__init__(self, win)

        self.resize(500, 400)

        spl = QSplitter(Qt.Orientation.Vertical)

        top_pane = QVBoxLayout()
        top_pane.setContentsMargins(0, 0, 0, 0)

        # Init ahead of time so that it may be populated in the RB handler
        entries = self.entries = QTableView()
        details = self.details = QTableView()

        self.make_top(top_pane)

        entries.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        entries.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        top_pane.addWidget(entries)
        w = QWidget()
        w.setLayout(top_pane)
        spl.addWidget(w)

        details.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems) # Double click to zoom in on expression
        details.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        bottom_pane = QVBoxLayout()
        bottom_pane.setContentsMargins(0, 0, 0, 0)
        bottom_pane.addWidget(details)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        #self.nav_bu = QPushButton("Navigate", self)
        #self.nav_bu.clicked.connect(self.on_navigate)
        #self.nav_bu.setEnabled(False)
        #buttons.addButton(self.nav_bu, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        bottom_pane.addWidget(buttons)
        w = QWidget()
        w.setLayout(bottom_pane)
        spl.addWidget(w)

        spl.setStretchFactor(0, 1)
        spl.setStretchFactor(1, 0)
        ly = QVBoxLayout()
        ly.addWidget(spl)
        self.setLayout(ly)

        self.setWindowTitle('Frames')

    def make_top(self, top_pane):
        pass

class FramesDlg(FramesUIDlg):
    def __init__(self, win, cfi, di, regnames, hex):
        self.cfi = cfi
        self.dwarfinfo = di
        self.hex = hex
        arch = di.config.machine_arch
        self.regnamelist = _REG_NAME_MAP.get(arch, None) if not regnames else None
        dwarf_version = 2 # If no debug sections, can't tell if it's V1. Frames were not in V1.
        self.expr_parser = DWARFExprParser(di.structs)
        self.expr_formatter = ExprFormatter(regnames, False, arch, dwarf_version, True)

        FramesUIDlg.__init__(self, win)

        # Expression details browser
        self.details.doubleClicked.connect(self.on_rule_dclick)

    def on_entry_sel(self, index, prev = None):
        # TODO: raw mode
        self.details.setModel(DecodedEntryModel(index.internalPointer(), self.regnamelist, self.expr_parser, self.expr_formatter))

    def on_rule_dclick(self, index):
        if index and index.isValid():
            model = self.details.model()
            rule = model.get_expr_rule(index)
            if rule:
                regname = model.get_regname_by_index(index)
                pc = index.internalPointer()['pc'] # :(
                target = regname if rule.type == 'VAL_EXPRESSION' else f'address of {regname}'
                title = f'Expression for {target} at/past 0x{pc:x}'
                ExpressionDlg(self, title, rule.expr, self.expr_formatter).exec()

    def make_top(self, top_pane):
        top_pane.addWidget(make_rbutton_pair(("Ranges", "Entries"), self.set_view))        

    def set_view(self, fdes_only):
        # TODO: change the model in place
        self.entries.setModel(EntriesModel(self.cfi, fdes_only, self.hex))
        self.entries.selectionModel().currentChanged.connect(self.on_entry_sel)
        self.details.setModel(None)

def make_rbutton_pair(titles, on_toggle):
    bu_line = QHBoxLayout()
    rbus = QButtonGroup()
    rbu = QRadioButton()
    rbu.setText(titles[0])
    rbu.toggled.connect(lambda c: on_toggle(True))
    rbu.setChecked(True)
    rbus.addButton(rbu)
    bu_line.addWidget(rbu)
    rbu = QRadioButton()
    rbu.setText(titles[1])
    rbu.toggled.connect(lambda c: on_toggle(False))
    rbus.addButton(rbu)
    bu_line.addWidget(rbu)
    w = QWidget()
    w.setLayout(bu_line)
    return w