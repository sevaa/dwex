from PyQt6.QtCore import Qt, QAbstractTableModel, QSize
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QFontInfo, QFont
from elftools.dwarf.locationlists import LocationParser, LocationExpr

from dwex.exprutil import ExprFormatter
from .dwarfutil import *

#0x25af0
#0xd864 (black)
#0xdc6e (lxxx)
#TODO: refactor away C++, support C explicitly
#TODO: Objective C, Pascal, more?

headers = ["Name", "Location"]
_bold_font = None

# TODO: move elsewhere
class WaitCursor():
    def __enter__(self):
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

    def __exit__(self, *args):
        QApplication.restoreOverrideCursor()

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
                if len(val) == 0:
                    return '<N/A>'
                elif len(val) > 3: # Variable
                    return "; ".join(self.expr_formatter.format_op(*op) for op in val[0:3]) + "...+%d" % (len(val)-3)
                else:
                    return "; ".join(self.expr_formatter.format_op(*op) for op in val)
            return val
        elif role == Qt.ItemDataRole.FontRole:
            if the_row[0]:
                global _bold_font
                if not _bold_font:
                    fi = QFontInfo(QApplication.font())
                    _bold_font = QFont(fi.family(), fi.pointSize(), QFont.Weight.Bold)
                return _bold_font
        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == 1:
                if len(val) == 0:
                    return 'The variable was optimized away at the provided address'
                elif len(val) > 3:
                    return "; ".join(self.expr_formatter.format_op(*op) for op in val)

############################################################################

class LocalsDlg(QDialog):
    _last_address = '' # Stored as string to allow for blank
    _last_start_address = 0 # Stored as int

    def __init__(self, win, di, prefix, regnames, hexadecimal):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
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
        self.locals.doubleClicked.connect(self.on_dclick)
        ly.addWidget(self.locals)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        self.nav_bu = QPushButton("Navigate", self)
        self.nav_bu.clicked.connect(self.on_navigate)
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
                    address = int(self.address.text(), 0)
                    real_start_address = int(self.start_address.text(), 0)
                except ValueError:
                    return
                
                LocalsDlg._last_address = self.address.text()
                LocalsDlg._last_start_address = real_start_address

                preferred_start_address = self.dwarfinfo._start_address
                address += preferred_start_address - real_start_address # Now relative to the preferred start address
                self.expr_formatter.set_address_delta(real_start_address - preferred_start_address) # Relocate addr on the way out

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
                file_and_line = get_source_line(func, address)
                if file_and_line is None:
                    file_and_line = ("?","?")

                (func_name, mangled_func_name) = retrieve_function_names(func_desc, func)

                grid_lines = [(True, func_name, '%s:%d' % file_and_line, func)]
                while func: # Loop by function; inside the top level one there might be inlines
                    ver = func.cu['version'] # The variable should not be in a different CU than the containing function
                    (locals, func) = scan_scope(func, address)
                    self.expr_formatter.dwarf_version = ver
                    grid_lines += [(False, name,  expr, die) for (name, expr, die) in locals]
                    if func: # Found a nested inline function, move on to that
                        (inline_func, inline_func_spec) = follow_function_spec(func)
                        (inline_func_name, mangled_inline_func_name) = retrieve_function_names(inline_func_spec, inline_func)
                        inline_decl_file = get_source_file_name_from_attr(inline_func_spec, 'DW_AT_decl_file') or '?'
                        inline_decl_line = inline_func_spec.attributes['DW_AT_decl_line'].value if 'DW_AT_decl_line' in inline_func_spec.attributes else '?'
                        grid_lines.append((True, inline_func_name, '%s:%d' % (inline_decl_file, inline_decl_line), func))

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
        except Exception as exc:
            QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer", 
                "Unexpected error while analysing the debug information.", QMessageBox.StandardButton.Ok, self).show()
            
    def on_navigate(self):
        row = self.locals.currentIndex().row()
        self.selected_die = self.locals.model().data[row][3]
        self.done(QDialog.DialogCode.Accepted)

    def on_dclick(self, index):
        row = index.row()
        self.selected_die = self.locals.model().data[row][3]
        self.done(QDialog.DialogCode.Accepted)        

    def on_sel(self, index, prev = None):
        self.nav_bu.setEnabled(index.isValid())

    @classmethod
    def reset(cl, di):
        cl._last_start_address = di._start_address
        cl._last_address = ''

