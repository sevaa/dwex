from PyQt6.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
from PyQt6.QtWidgets import *
from PyQt6.QtGui import QFontInfo, QFont
from elftools.dwarf.locationlists import LocationParser, LocationExpr

from dwex.exprutil import ExprFormatter
from .dwarfutil import *

#0x25af0
#0xd864

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

class LocalsModel(QAbstractTableModel):
    # Data is a list (is_scope, name, location, die)
    def __init__(self, data):
        QAbstractTableModel.__init__(self)
        self.data = data

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return headers[section]

    def rowCount(self, parent):
        return len(self.data)

    def columnCount(self, parent):
        return 2

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            return self.data[index.row()][index.column()+1]
        elif role == Qt.ItemDataRole.FontRole:
            if self.data[index.row()][0]:
                global _bold_font
                if not _bold_font:
                    fi = QFontInfo(QApplication.font())
                    _bold_font = QFont(fi.family(), fi.pointSize(), QFont.Weight.Bold)
                return _bold_font

class LocalsDlg(QDialog):
    def __init__(self, win, di, prefix, regnames):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.dwarfinfo = di
        if di._locparser is None:
            di._locparser = LocationParser(di.location_lists())
        if not di._ranges:
            di._ranges = di.range_lists()            
        if not di._aranges:
            di._aranges = di.get_aranges()

        self.expr_formatter = ExprFormatter(regnames, prefix, di.config.machine_arch, 2) # Version is unknowable for now

        ly = QVBoxLayout()
        l = QLabel(self)
        l.setText("Provide a hex code address:")
        ly.addWidget(l)
        self.address = QLineEdit(self)
        ly.addWidget(self.address)
        l = QLabel(self)
        l.setText("Assuming the module is loaded at:")
        ly.addWidget(l)
        self.start_address = QLineEdit(hex(di._start_address), self)
        ly.addWidget(self.start_address)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Apply, self)
        buttons.clicked.connect(self.on_check)
        ly.addWidget(buttons)

        self.locals = QTableView()
        self.locals.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        ly.addWidget(self.locals)        

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)
        self.setWindowTitle('Locals at address')
        self.setLayout(ly)

    def on_check(self, bu):
        try: # Try of just in case
            with WaitCursor():
                try:
                    address = int(self.address.text(), 0)
                    load_address = int(self.start_address.text(), 0)
                except ValueError:
                    return

                start_address = self.dwarfinfo._start_address
                address += start_address - load_address # Now relative to the preferred start address

                # Find the CU for the address
                di = self.dwarfinfo
                cu = find_cu_by_address(di, address)
                if cu is None:
                    return
                
                # Find the function(s) at the address - could be some inlines
                funcs = find_funcs_at_address(cu, address, start_address)
                if not funcs:
                    return

                if len(funcs) != 1:
                    raise SeveralFunctionsError()

                func = funcs[0]
                (origin, func_desc) = follow_function_spec(func)
                file_and_line = get_source_line(func, address)
                if file_and_line is None:
                    file_and_line = ("?","?")

                (func_name, mangled_func_name) = retrieve_function_names(func_desc, func)

                grid_lines = [(True, func_name, '%s:%d' % file_and_line)]
                while func: # Loop by function; inside the top level one there might be inlines
                    ver = func.cu['version'] # The variable should not be in a different CU than the containing function
                    (locals, func) = scan_scope(func, address)
                    self.expr_formatter.dwarf_version = ver
                    grid_lines += [(False, name,  "; ".join(self.expr_formatter.format_op(*op) for op in expr)) for (name, expr) in locals]
                    if func: # Found a nested inline function, move on to that
                        (inline_func, inline_func_spec) = follow_function_spec(func)
                        (inline_func_name, mangled_inline_func_name) = retrieve_function_names(inline_func_spec, inline_func)
                        grid_lines.append((True, inline_func_name, '?'))

                # Finally display
                self.locals.setModel(LocalsModel(grid_lines))
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



