from PyQt6.QtCore import Qt, QAbstractTableModel, QSize
from PyQt6.QtWidgets import *
from elftools.dwarf.locationlists import LocationParser, LocationExpr
from elftools.dwarf.callframe import FDE, CFARule

from dwex.exprutil import ExprFormatter, format_offset
from .dwarfutil import *
from .fx import bold_font, WaitCursor

#0x25af0
#0xd864 (black)
# test: d989, n with False for expression
#0xdc6e (lxxx)
#TODO: refactor away C++, support C explicitly
#TODO: Objective C, Pascal, more?

#TODO: saved registers from unwind info

headers = ["Name", "Location"]

class SeveralFunctionsError(Exception):
    pass

#######################################################################

class LocalsModel(QAbstractTableModel):
    # Data is a list (is_scope, name, location, die)
    def __init__(self, data, expr_formatter):
        QAbstractTableModel.__init__(self)
        self.data = data
        self.expr_formatter = expr_formatter

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return headers[section]

    def rowCount(self, parent):
        return len(self.data)

    def columnCount(self, parent):
        return 2

    def data(self, index, role):
        (row, col) = (index.row(), index.column())
        the_row = self.data[row]
        val = the_row[col+1]
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 1 and not the_row[0]: # Location on a variable
                if val is False: # No location
                    return '<N/A>'
                elif len(val) == 0: # Loclist, but not for the given address
                    return '<N/A>'
                elif len(val) > 3: # Variable
                    return "; ".join(self.expr_formatter.format_op(*op) for op in val[0:3]) + "...+%d" % (len(val)-3)
                else:
                    return "; ".join(self.expr_formatter.format_op(*op) for op in val)
            return val
        elif role == Qt.ItemDataRole.FontRole:
            if the_row[0]:
                return bold_font()
        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == 1 and not the_row[0]: # On the location column of a variable
                if val is False:
                    return 'No location provided'
                elif len(val) == 0:
                    return 'The variable was optimized away at the provided address'
                elif len(val) > 3:
                    return "; ".join(self.expr_formatter.format_op(*op) for op in val)

############################################################################
class LoadedModuleDlgBase(QDialog):
    _last_start_address = 0 # Stored as int

    def __init__(self, win):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)

    @classmethod
    def reset(cl, di):
        cl._last_start_address = di._start_address

#############################################################################

class LocalsDlg(LoadedModuleDlgBase):
    _last_address = '' # Stored as string to allow for blank
    
    def __init__(self, win, di, prefix, regnames, hexadecimal):
        LoadedModuleDlgBase.__init__(self, win)
        self.selected_die = False
        self.resize(500, 400)
        self.dwarfinfo = di
        if di._locparser is None:
            di._locparser = LocationParser(di.location_lists())
        if not di._ranges:
            di._ranges = di.range_lists()            
        if not di._aranges:
            di._aranges = di.get_aranges()

        self.expr_formatter = ExprFormatter(regnames, prefix, di.config.machine_arch, 2, hexadecimal) # DWARF version is unknowable for now

        ly = QVBoxLayout()
        l = QLabel(self)
        l.setText("Provide a hex code address:")
        ly.addWidget(l)
        self.address = QLineEdit(self._last_address, self)
        ly.addWidget(self.address)
        l = QLabel(self)
        l.setText("Assuming the module is loaded at:")
        ly.addWidget(l)
        self.start_address = QLineEdit(hex(self._last_start_address), self)
        ly.addWidget(self.start_address)

        buttons = QDialogButtonBox(self)
        bu = QPushButton("Check", self)
        bu.clicked.connect(self.on_check)
        buttons.addButton(bu, QDialogButtonBox.ButtonRole.ApplyRole)
        ly.addWidget(buttons)

        self.locals = QTableView()
        self.locals.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.locals.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.locals.doubleClicked.connect(self.navigate_to_index)
        ly.addWidget(self.locals)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        self.nav_bu = QPushButton("Navigate", self)
        self.nav_bu.clicked.connect(lambda: self.navigate_to_index(self.locals.currentIndex()))
        self.nav_bu.setEnabled(False)
        buttons.addButton(self.nav_bu, QDialogButtonBox.ButtonRole.ApplyRole)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)
        self.setWindowTitle('Locals at address')
        self.setLayout(ly)

    def on_check(self): #TODO: relocate absolute addresses in expressions
        try: # Try of just in case
            with WaitCursor():
                self.nav_bu.setEnabled(False) # Even if error, stay disabled

                try:
                    # Hex, with or without the 0x prefix
                    address = int(self.address.text(), 16)
                    real_start_address = int(self.start_address.text(), 16)
                except ValueError:
                    return
                
                LocalsDlg._last_address = self.address.text()
                LocalsDlg._last_start_address = real_start_address

                preferred_start_address = self.dwarfinfo._start_address
                address += preferred_start_address - real_start_address # Now relative to the preferred start address
                self.expr_formatter.set_address_delta(real_start_address - preferred_start_address) # Relocate addr on the way out
                self.expr_formatter.cfa_resolver = lambda: self.resolve_cfa(address)

                # Find the CU for the address
                di = self.dwarfinfo
                funcs = False
                cu = find_cu_by_address(di, address)
                if cu is not None:
                    # Find the function(s) at the address - could be some inlines
                    funcs = find_funcs_at_address(cu, address)
                
                if not funcs: # No CUs or no functions at that IP
                    QMessageBox(QMessageBox.Icon.Information, "DWARF Explorer", 
                        "No functions were found at that code address.", QMessageBox.StandardButton.Ok, self).show()
                    return

                if len(funcs) != 1:
                    raise SeveralFunctionsError()

                func = funcs[0]
                (origin, func_desc) = follow_function_spec(func)
                # This the file:line of the IP. It points at the innermost inline
                file_and_line = get_source_line(func, address)
                (address_file, address_line) = ("(unknown)",0) if file_and_line is None else file_and_line
                (func_name, mangled_func_name) = retrieve_function_names(func_desc, func)

                frames = [] # a collection of (func_name, file, line, die, locals), innermost at the top
                while True: # Loop by function from outermost to innermost; inside the top level one there might be inlines
                    (locals, next_func) = scan_scope(func, address)
                    if next_func: # Found a nested inline function, move on to that
                        call_file = get_source_file_name_from_attr(next_func, 'DW_AT_call_file') or '?'
                        call_line = next_func.attributes['DW_AT_call_line'].value if 'DW_AT_call_line' in next_func.attributes else '?'
                        frames.insert(0, (func_name, call_file, call_line, func, locals))
                        func = next_func
                        (inline_func, inline_func_spec) = follow_function_spec(func)
                        (func_name, mangled_func_name) = retrieve_function_names(inline_func_spec, inline_func)
                    else:
                        frames.insert(0, (func_name, address_file, address_line, func, locals))
                        break

                # Now render to lines:
                grid_lines = []
                for (name, file, line, func_die, locals) in frames:
                    grid_lines.append((True, name, '%s:%d' % (file, line), func_die))
                    self.expr_formatter.dwarf_version = func_die.cu['version'] # The variable should not be in a different CU than the containing function
                    for (name, expr, die) in locals:
                        grid_lines.append((False, name,  expr, die))

                # Finally display
                self.locals.setModel(LocalsModel(grid_lines, self.expr_formatter))
                self.locals.selectionModel().currentChanged.connect(self.on_sel)
                header = self.locals.horizontalHeader()
                header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
                header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        except SeveralFunctionsError:
            QMessageBox(QMessageBox.Icon.Warning, "DWARF Explorer", 
                "Expected one function with that address, found %d." % (len(funcs),), QMessageBox.StandardButton.Ok, self).show()
        except NoBaseError:
            # Any user followup maybe?
            QMessageBox(QMessageBox.Icon.Warning, "DWARF Explorer", 
                "Unexpected error while analysing the debug information." % (len(funcs),), QMessageBox.StandardButton.Ok, self).show()
        except NotImplementedError as exc:
            QMessageBox(QMessageBox.Icon.Warning, "DWARF Explorer", 
                "This feature is not supported on DWARF v1 yet.", QMessageBox.StandardButton.Ok, self).show()
        except Exception as exc:
            QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer", 
                "Unexpected error while analysing the debug information.", QMessageBox.StandardButton.Ok, self).show()

    def navigate_to_index(self, index):
        row = index.row()
        self.selected_die = self.locals.model().data[row][3]
        self.done(QDialog.DialogCode.Accepted)

    def on_sel(self, index, prev = None):
        self.nav_bu.setEnabled(index.isValid())

    def resolve_cfa(self, address):
        di = self.dwarfinfo
        if di.has_CFI():
            entries = di.CFI_entries()
        elif di.has_EH_CFI():
            entries = di.EH_CFI_entries()
        else:
            return False
        
        for e in entries:
            if isinstance(e, FDE) and e.header.initial_location <= address < e.header.initial_location + e.header.address_range:
                decoded = e.get_decoded().table
                de = next(reversed([de for de in decoded if de['pc'] <= address]))
                if 'cfa' in de:
                    rule = de['cfa']
                    if isinstance(rule, CFARule):
                        if rule.expr:
                            return 'expr'
                        else:
                            return self.expr_formatter.regname(rule.reg) + format_offset(rule.offset)
                    else:
                        return 'unknown'

    @classmethod
    def reset(cl):
        cl._last_address = ''

