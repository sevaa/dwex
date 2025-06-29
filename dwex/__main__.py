from bisect import bisect_left
import sys, os
from PyQt6.QtCore import Qt, QModelIndex, QSettings, QUrl, QEvent
from PyQt6.QtGui import QFontMetrics, QDesktopServices, QWindow
from PyQt6.QtWidgets import *

from .die import DIETableModel, on_details_row_dclick
from .formats import read_dwarf, get_debug_sections, load_companion_executable, FormatError, section_bytes, write_to_file
from .dwarfutil import get_code_location, get_di_frames, has_code_location, ip_in_range, quote_filename, subprogram_name
from .tree import DWARFTreeModel, cu_sort_key
from .scriptdlg import ScriptDlg, make_execution_environment
from .ui import setup_explorer, setup_ui
from .locals import LocalsDlg, LoadedModuleDlgBase
from .aranges import ArangesDlg
from .frames import FramesDlg
from .unwind import UnwindDlg
from .funcmap import FuncMapDlg, GatherFuncsThread
from .fx import WaitCursor, ArrowCursor
from .treedlg import TreeDlg

# Sync with version in setup.py
version = (4, 54)
the_app = None

# TODO:
# On MacOS, start without a main window, instead show the Open dialog

#-----------------------------------------------------------------
# The one and only main window class
# Pretty much DWARF unaware, all the DWARF visualization logic is in tree.py and die.py
#-----------------------------------------------------------------

# "Opened, could not parse"
class DWARFParseError(Exception):
    def __init__(self, exc, di):
        Exception.__init__(self, "DWARF parsing error: " + format(exc))
        self.dwarfinfo = di

class TheWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sett = None
        self.in_tree_nav = False
        self.font_metrics = QFontMetrics(QApplication.font())

        self.load_settings()
        setup_ui(self)
        self.setAcceptDrops(True)

        # The data model placeholders - to be populated once we read a file
        self.dwarfinfo = None
        self.tree_model = None # Recreated between files
        self.die_model = None # Reused between DIEs

        self.findcondition = None
        self.findcucondition = None

        self.show()

        # Command line: if can't open, print the error to console
        # On Mac/Linux, the user will see it. On Windows, they won't.
        if len(sys.argv) > 1:
            try:
                if self.open_file(sys.argv[1]) is None:
                    print("The file contains no DWARF information, or it is in an unsupported format.")
            except Exception as exc:
                print(format(exc))
        elif os.environ.get("DWEX_LOADLAST") is not None and len(self.mru) > 0:
            fa = self.mru[0]
            if os.path.exists(fa[0]):
                self.open_file(fa[0], fa[1:])


    def load_settings(self):
        self.sett = sett = QSettings('Seva', 'DWARFExplorer')
        self.prefix = sett.value('General/Prefix', False, type=bool)
        self.lowlevel = sett.value('General/LowLevel', False, type=bool)
        self.hex = sett.value('General/Hex', False, type=bool)
        self.sortcus = sett.value('General/SortCUs', True, type=bool)
        self.sortdies = sett.value('General/SortDIEs', False, type=bool)
        self.dwarfregnames = sett.value('General/DWARFRegNames', False, type=bool)
        self.mru = []
        for i in range(0, 10):
            f = sett.value("General/MRU%d" % i, False)
            if f:
                arch = sett.value("General/MRUArch%d" % i, None)
                fn = sett.value("General/MRUArchA%d" % i, None)
                fa = (f,) if arch is None else (f, arch) if fn is None else (f, arch, fn)
                self.mru.append(fa)
        theme = sett.value("General/Theme", None, type=str)
        if theme and theme in QStyleFactory.keys():
            QApplication.setStyle(QStyleFactory.create(theme))

    ###################################################################
    # Done with init, now file stuff
    ###################################################################

    # Callback for the Mach-O fat binary opening logic
    # Taking a cue from Hopper or IDA, we parse only one slice at a time
    # arches is a list of strings in the simple case,
    # list of strings and tuples in the tree case (Mach-O fat library)
    def resolve_arch(self, arches, title, message):
        with ArrowCursor():
            if any(not isinstance(a, str) for a in arches):
                dlg = TreeDlg(self, title, arches)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    mi = dlg.selection
                    return mi[0] if len(mi) == 1 else mi
            else:
                r = QInputDialog.getItem(self, title, message, arches, 0, False, Qt.WindowType.Dialog)
                return arches.index(r[0]) if r[1] else None
    
    # Can throw an exception
    # Returns None if it doesn't seem to contain DWARF
    # False if the user cancelled
    # True if the DWARF tree was loaded
    def open_file(self, filename, slice = None):
        with WaitCursor():
            def recall_slice(slices, title, text):
                if len(slice) == 1:
                    return slices.index(slice[0])
                else: # arch is a tuple, assuming no more than two levels
                    (arch, fn) = slice
                    (i, a) = next(ia for ia in enumerate(slices) if ia[1][0] == arch)
                    j = a[1].index(fn)
                    return (i, j)
            di = read_dwarf(filename, self.resolve_arch if slice is None else recall_slice)
            if not di: # Covers both False and None
                return di
            
            return self.load_dwarfinfo(di, filename)

    # May throw if parsing fails
    def load_dwarfinfo(self, di, filename):
        # Some degree of graceful handling of wrong format
        # File name in case of Mach-O bundles refers to the bundle path, not to the binary path within
        try:
            #TODO, slice
            slice_code = di._slice_code if hasattr(di, '_slice_code') else None
            # Some cached top level stuff
            # Notably, iter_CUs doesn't cache (TODO, check that in the next version)
            di._ranges = None # Loaded on first use
            di._aranges = None
            di._frames = None # Loaded on first use, False means missing
            def decorate_cu(cu, i):
                cu._i = i
                cu._lineprogram = None
                cu._exprparser = None
                return cu
            di._unsorted_CUs = [decorate_cu(cu, i) for (i, cu) in enumerate(di.iter_CUs())] # We'll need them first thing, might as well load here

            # For quick CU search by offset within the info section, regardless of sorting
            di._CU_offsets = [cu.cu_offset for cu in di._unsorted_CUs]
            di._CUs = list(di._unsorted_CUs)

            if self.sortcus:
                di._CUs.sort(key = cu_sort_key)
                for (i, cu) in enumerate(di._CUs):
                    cu._i = i
            di._locparser = None # Created on first use - but see #1683

            if self.dwarfinfo is None:
                setup_explorer(self)
            self.dwarfinfo = di
            self.filename = filename
            has_CUs = bool(len(di._unsorted_CUs))
            if has_CUs:
                self.tree_model = DWARFTreeModel(di, self.prefix, self.sortcus, self.sortdies)
                self.the_tree.setModel(self.tree_model)
                self.the_tree.selectionModel().currentChanged.connect(self.on_tree_selection)
            else: # Loading a binary with no CUs - possible
                self.tree_model = None
                self.the_tree.setModel(None)
                self.die_table.setModel(None)
                self.details_table.setModel(None)
            s = os.path.basename(filename)
            if slice_code is not None:
                s += ' (' + ':'.join(slice_code) + ')'
            self.setWindowTitle("DWARF Explorer - " + s)
            # TODO: unite "enable on file load" into a collection
            self.savesection_menuitem.setEnabled(True)
            self.switchslice_menuitem.setEnabled(slice_code is not None)
            self.loadexec_menuitem.setEnabled(di._format in (1, 5))
            self.back_menuitem.setEnabled(False)
            self.back_tbitem.setEnabled(False)
            self.forward_menuitem.setEnabled(False)
            self.forward_tbitem.setEnabled(False)
            self.followref_menuitem.setEnabled(False)
            self.followref_tbitem.setEnabled(False)
            self.highlightcode_menuitem.setEnabled(has_CUs)
            self.highlightsubstring_menuitem.setEnabled(has_CUs)
            self.highlightcondition_menuitem.setEnabled(has_CUs)
            self.highlightnothing_menuitem.setEnabled(has_CUs)
            self.copy_menuitem.setEnabled(False)
            self.copy_tbitem.setEnabled(False)
            self.copyline_menuitem.setEnabled(False)
            self.copytable_menuitem.setEnabled(False)
            self.findbycondition_menuitem.setEnabled(has_CUs)
            self.find_menuitem.setEnabled(has_CUs)
            self.find_tbitem.setEnabled(has_CUs)
            self.findip_menuitem.setEnabled(has_CUs)
            self.byoffset_menuitem.setEnabled(has_CUs)
            self.byoffset_tbitem.setEnabled(has_CUs)
            self.localsat_menuitem.setEnabled(has_CUs)
            self.funcmap_menuitem.setEnabled(has_CUs)
            self.aranges_menuitem.setEnabled(has_CUs)
            self.frames_menuitem.setEnabled(True)
            self.unwind_menuitem.setEnabled(di._format in (1, 5))
            self.on_highlight_nothing()
            # Navigation stack - empty
            self.navhistory = []
            self.navpos = -1
            self.save_filename_in_mru(filename, slice_code)
            LoadedModuleDlgBase.reset(di)
            LocalsDlg.reset()
            from .crash import set_binary_desc
            set_binary_desc(("ELF", "MachO", "PE", "WASM", "ELFinA", "MachOinA", "MachOinAinFat")[di._format] + " " + di.config.machine_arch)
            return True
        except AssertionError as ass: # Covers exeptions during parsing
            raise DWARFParseError(ass, di)        

    def save_mru(self):
        for i, fa in enumerate(self.mru):
            self.sett.setValue("General/MRU%d" % i, fa[0])    

            if len(fa) > 2:
                self.sett.setValue("General/MRUArchA%d" % i, fa[2])
            else:
                self.sett.remove("General/MRUArchA%d" % i)

            if len(fa) > 1:
                self.sett.setValue("General/MRUArch%d" % i, fa[1])
            else:
                self.sett.remove("General/MRUArch%d" % i)

        for i in range(len(self.mru), 10):
            self.sett.remove("General/MRU%d" % i)
            self.sett.remove("General/MRUArch%d" % i)
            self.sett.remove("General/MRUArchA%d" % i)

    # Open a file, display an error if failure
    # Called from menu/File/Open, toolbar/Open, File/MRU, and the drop handler. MRU provides the arch
    def open_file_interactive(self, filename, arch = None):
        try:
            if self.open_file(filename, arch) is None:
                if os.path.isdir(filename):
                    s = "The directory (bundle) could not be resolved to a DWARF containing file, or the file contains no DWARF information. Try navigating inside and open the executable file directly."
                else:
                    s = "The file contains no DWARF information, or it is in an unsupported format."
                self.show_warning(s)
        except FormatError as ferr:
            self.show_warning(str(ferr))
        except DWARFParseError as dperr:
            mb = QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer",
                "Error parsing the DWARF information in this file. Would you like to save the debug section contents for manual analysis?",
                QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No, self)
            mb.setEscapeButton(QMessageBox.StandardButton.No)
            r = mb.exec()
            if r == QMessageBox.StandardButton.Yes:
                self.save_sections(filename, dperr.dwarfinfo)
        except Exception as exc:
            QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer",
                "Error opening the file:\n\n" + format(exc),
                QMessageBox.StandardButton.Ok, self).show()
            
    def save_sections(self, filename, di):
        dir = QFileDialog.getExistingDirectory(self, "Choose a save location", os.path.dirname(filename))
        if dir:
            sections = get_debug_sections(di)
            basename = os.path.basename(filename)
            overwrite_all = False
            for (name, section) in sections.items():
                try:
                    section_file = os.path.join(dir, basename + '.' + name)
                    skip = False
                    if os.path.exists(section_file) and not overwrite_all:
                        mb = QMessageBox(QMessageBox.Icon.Question, "DWARF Explorer",
                            "File %s exists, overwrite?" % section_file,
                            QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.YesAll|QMessageBox.StandardButton.No|QMessageBox.StandardButton.Cancel, self)
                        mb.setEscapeButton(QMessageBox.StandardButton.Cancel)
                        r = mb.exec()
                        if r == QMessageBox.StandardButton.Cancel:
                            return
                        elif r == QMessageBox.StandardButton.YesAll:
                            overwrite_all = True
                        elif r == QMessageBox.StandardButton.No:
                            skip = True
                    if not skip:
                        write_to_file(section_file, section_bytes(section))
                except:
                    pass

    # TODO: list the extensions for the open file dialog?
    def on_open(self):
        dir = os.path.dirname(self.mru[0][0]) if len(self.mru) > 0 else ''
        filename = QFileDialog.getOpenFileName(self, None, dir)
        if filename[0]:
            self.open_file_interactive(os.path.normpath(filename[0]))

    def on_loadexec(self):
        dir = os.path.dirname(self.mru[0][0]) if len(self.mru) > 0 else ''
        filename = QFileDialog.getOpenFileName(self, None, dir)
        if filename[0]:
            try:
                load_companion_executable(filename[0], self.dwarfinfo)
            except FormatError as exc:
                self.show_warning(str(exc))

    def populate_mru_menu(self):
        class MRUHandler(object):
            def __init__(self, fn, sc, win):
                object.__init__(self)
                self.fn = fn
                self.sc = sc
                self.win = win
            def __call__(self):
                if os.path.exists(self.fn):
                    self.win.open_file_interactive(self.fn, self.sc)
                else:
                    mb =  QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer",
                        f"The file or bundle {self.fn} does not exist or is not accessible. Shall we remove it from the recent file menu?",
                        QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No, self.win)
                    mb.setEscapeButton(QMessageBox.StandardButton.No)
                    r = mb.exec()
                    if r == QMessageBox.StandardButton.Yes:
                        self.win.delete_from_mru((self.fn,) if self.sc is None else (self.fn,) + self.sc)

        for i, fnsc in enumerate(self.mru):
            s = fn = fnsc[0]
            if len(fnsc) > 1:
                slice_code = fnsc[1:]
                s += ' (' + ':'.join(slice_code) + ')'
            else:
                slice_code = None
            self.mru_menu.addAction(s).triggered.connect(MRUHandler(fn, slice_code, self))

    # slice_code is a tuple
    def save_filename_in_mru(self, filename, slice_code = None):
        mru_record = (filename,) if slice_code is None else (filename,) + slice_code
        try:
            i = self.mru.index(mru_record)
        except ValueError:
            i = -1
        if i != 0:
            if i > 0:
                self.mru.pop(i)
            self.mru.insert(0, mru_record)
            if len(self.mru) > 10:
                self.mru = self.mru[0:10]
            self.save_mru()
            self.mru_menu.setEnabled(True)
            self.mru_menu.clear()
            self.populate_mru_menu()

    def delete_from_mru(self, mru_record):
        try:
            self.mru.remove(mru_record) # ValueError if not found
            self.save_mru()
            self.mru_menu.setEnabled(len(self.mru) > 0)
            self.mru_menu.clear()
            self.populate_mru_menu()
        except ValueError:
            pass

    # File drag/drop handling - equivalent to open
    def dragEnterEvent(self, evt):
        if evt.mimeData() and evt.mimeData().hasUrls() and len(evt.mimeData().urls()) == 1:
            evt.accept()

    def dropEvent(self, evt):
        self.open_file_interactive(os.path.normpath(evt.mimeData().urls()[0].toLocalFile()))

    # Save sections as
    def on_savesection(self):
        di = self.dwarfinfo
        # Maps display name to field name in DWARFInfo
        sections = get_debug_sections(di)
        
        names = sections.keys()
        r = QInputDialog.getItem(self, 'Save a Section', 'Choose a section:', names, 0, False, Qt.WindowType.Dialog)
        if r[1]:
            section_name = r[0]
            r = QFileDialog.getSaveFileName(self, "Save a section", self.filename + '.' + section_name)
            if r[0]:
                try:
                    write_to_file(r[0], section_bytes(sections[section_name]))
                except Exception as exc:
                    QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer",
                        "Error saving the section data:\n\n" + format(exc),
                        QMessageBox.StandardButton.Ok, self).show()
    
    # Just present the slice dialog again
    # TODO: do this in a more elegant way, without reopening and rereading
    def on_switchslice(self):
        self.open_file(self.filename, None)

    #############################################################
    # Done with file stuff, now tree navigation
    #############################################################     

    # Index is a tree index - the DIE is the data object within
    def display_die(self, index):
        if self.details_table and self.die_table: # Short out for #1753
            die = index.internalPointer()
            die_table = self.die_table
            if not self.die_model:
                self.die_model = DIETableModel(die, self.prefix, self.lowlevel, self.hex, self.dwarfregnames)
                die_table.setModel(self.die_model)
                die_table.selectionModel().currentChanged.connect(self.on_attribute_selection)
            else:
                self.die_model.display_DIE(die)
            self.die_table.resizeColumnsToContents()
            self.details_table.setModel(None)
            self.followref_menuitem.setEnabled(False)
            self.followref_tbitem.setEnabled(False)
            self.cuproperties_menuitem.setEnabled(True)
            self.die_table.setCurrentIndex(QModelIndex()) # Will cause on_attribute_selection

            #TODO: resize the attribute table vertically dynamically
            #attr_count = self.die_model.rowCount(None)
            #die_table.resize(die_table.size().width(),
            #    die_table.rowViewportPosition(attr_count-1) + 
            #        die_table.rowHeight(attr_count-1) +
            #        die_table.horizontalHeader().size().height() + 1 + attr_count)
            #self.rpane_layout.update()

    # Invoked for tree clicks and keyboard navigation, ref follow, back-forward
    def on_tree_selection(self, index, prev = None):
        if not self.in_tree_nav: # Short out the history population logic for back-forward clicks
            navitem = self.tree_model.get_navitem(index)
            if navitem: # Weird, should never happen - yet #1473
                self.navhistory[0:self.navpos] = [navitem]
                self.navpos = 0
                self.back_menuitem.setEnabled(len(self.navhistory) > 1)
                self.back_tbitem.setEnabled(len(self.navhistory) > 1)
                self.forward_menuitem.setEnabled(False)
                self.forward_tbitem.setEnabled(False)
        self.display_die(index) # Will clear the selection in the attribute table

    # Selection changed in the DIE table - either user or program
    def on_attribute_selection(self, index, prev = None):
        if index.isValid():
            details_model = self.die_model.get_attribute_details(index)
            self.details_table.setModel(details_model)
            if details_model is not None:
                self.details_table.resizeColumnsToContents()
                has_warning = hasattr(details_model, 'warning') and details_model.warning is not None
                self.details_warning.setVisible(has_warning)
                if has_warning:
                    self.details_warning.setText(details_model.warning)
            else:
                self.details_warning.setVisible(False)
            self.followref_menuitem.setEnabled(self.die_model.ref_target(index) is not None)
            self.followref_tbitem.setEnabled(self.die_model.ref_target(index) is not None)
            self.copy_menuitem.setEnabled(True)
            self.copy_tbitem.setEnabled(True)
            self.copyline_menuitem.setEnabled(True)
            self.copytable_menuitem.setEnabled(True)
        else: # Selected nothing
            self.details_table.setModel(None)
            self.copy_menuitem.setEnabled(False)
            self.copy_tbitem.setEnabled(False)
            self.copyline_menuitem.setEnabled(False)
            self.copytable_menuitem.setEnabled(False)            
            self.followref_menuitem.setEnabled(False)
            self.followref_tbitem.setEnabled(False)


    def on_attribute_dclick(self, index):
        self.followref(index)

    # For both back and forward, delta=1 for back, -1 for forward
    # Checked because back-forward buttons can't be disabled
    def on_nav(self, delta):
        if self.tree_model: # Maybe fix for #1461? Short out nav if no file loaded
            np = self.navpos + delta
            if np < 0 or np >= len(self.navhistory):
                return
            self.navpos = np
            navitem = self.navhistory[np]
            tree_index = self.tree_model.index_for_navitem(navitem)
            self.in_tree_nav = True
            self.the_tree.setCurrentIndex(tree_index) # Causes on_tree_selection internally
            self.in_tree_nav = False
            self.back_menuitem.setEnabled(np < len(self.navhistory) - 1)
            self.back_tbitem.setEnabled(np < len(self.navhistory) - 1)
            self.forward_menuitem.setEnabled(np > 0)
            self.forward_tbitem.setEnabled(np > 0)

    def followref(self, index = None):
        with WaitCursor():
            # TODO: only show the wait cursor if it's indeed time consuming
            if index is None:
                index = self.die_table.currentIndex()
            navitem = self.die_model.ref_target(index)  # Retrieve the ref target from the DIE model...
            if navitem:
                target_tree_index = self.tree_model.index_for_navitem(navitem) # ...and feed it to the tree model.
                if target_tree_index:
                    self.the_tree.setCurrentIndex(target_tree_index) # Calls on_tree_selection internally

    # Called for double-click on a reference type attribute, and via the menu
    def on_followref(self):
        self.followref()

    def on_details_dclick(self, index):
        if index.isValid():
            on_details_row_dclick(index, index.internalPointer(), self)

    ##########################################################################
    # Find/Find next stuff
    ##########################################################################

    def findbytext(self, die, s):
        for k in die.attributes.keys():
            attr = die.attributes[k]
            v = attr.value
            f = attr.form
            all = "\n".join((str(v), str(k), f, hex(v) if isinstance(v, int) else '')).lower()
            if all.find(s) >= 0:
                return True
        return False

    # Exception means false
    def eval_user_condition(self, cond, die):
        try:
            env = make_execution_environment(die)
        except Exception as exc: # Our error
            from .crash import report_crash
            from inspect import currentframe
            report_crash(exc, exc.__traceback__, version, currentframe())
            return False
        try:
            return eval(cond, env)
        except Exception as exc: # Error in condition or it assumes a different DIE structure 
            print("Error in user condition: %s" % format(exc))
            return False

    def on_find(self):
        r = QInputDialog.getText(self, 'Find', 'Find what:')
        if r[1] and r[0]:
            s = r[0].lower()
            self.findcondition = lambda die: self.findbytext(die, s)
            self.findcucondision = None
            self.findnext_menuitem.setEnabled(True)
            self.on_findnext()

    def on_findip(self):
        start_address = hex(self.dwarfinfo._start_address) if not self.dwarfinfo._start_address is None else "its preferred address"
        r = QInputDialog.getText(self, "Find code address", "Code address (hex), assuming the module is loaded at %s:" % start_address)
        if r[1] and r[0]:
            try:
                ip = r[0]
                if r[0].startswith("0x"):
                    ip = ip[2:]
                ip = int(ip, 16)
                self.findcondition = lambda die: ip_in_range(die, ip)
                self.findcucondition = lambda cu: ip_in_range(cu.get_top_DIE(), ip)
                self.findnext_menuitem.setEnabled(True)
                self.on_findnext()            
            except ValueError:
                pass

    def on_byoffset(self):
        r = QInputDialog.getText(self, "Find DIE by offset", "DIE offset (hex), relative to the section start:")
        if r[1] and r[0]:
            try:
                offset = int(r[0], 16)
                index = self.tree_model.find_offset(offset)
                if index:
                    self.the_tree.setCurrentIndex(index)
                else:
                    self.show_warning("The specified offset was not found. It could be beyond the section size, or fall into a CU header area.")
            except ValueError:
                pass

    def sample_die(self):
        return self.the_tree.currentIndex().internalPointer() or self.dwarfinfo._CUs[0].get_top_DIE()

    def on_findbycondition(self):
        dlg = ScriptDlg(self, self.sample_die())
        if dlg.exec() == QDialog.DialogCode.Accepted:
            cond = dlg.cond
            self.findcondition = lambda die: self.eval_user_condition(cond, die)
            self.findcucondition = None
            self.findnext_menuitem.setEnabled(True)
            self.on_findnext()

    def on_findnext(self):
        index = self.tree_model.find(self.the_tree.currentIndex(), self.findcondition, self.findcucondition)
        if index:
            self.the_tree.setCurrentIndex(index)

    def on_changetheme(self):
        themes = ["Default",] + QStyleFactory.keys()
        theme = self.sett.value('General/Theme', None, type=str)
        theme_no = themes.index(theme) if theme and theme in themes else 0
        r = QInputDialog.getItem(self, "Theme", "Please select the visual theme:", themes, theme_no, False, Qt.WindowType.Dialog)
        if r[1]:
            new_theme_no = themes.index(r[0])
            if new_theme_no == 0 and theme:
                self.sett.remove('General/Theme')
            elif new_theme_no > 0:
                self.sett.setValue('General/Theme', themes[new_theme_no])

            if new_theme_no > 0:
                QApplication.setStyle(QStyleFactory.create(themes[new_theme_no]))
            else:
                QApplication.setStyle(None)
    
    ##########################################################################
    ##########################################################################

    def on_about(self):
        QMessageBox(QMessageBox.Icon.Information, "About...", "DWARF Explorer v." + '.'.join(str(v) for v in version) + "\n\nSeva Alekseyev, 2020-2024\nsevaa@sprynet.com\n\ngithub.com/sevaa/dwex",
            QMessageBox.StandardButton.Ok, self).show()

    def on_updatecheck(self):
        from urllib.request import urlopen
        import json
        try:
            releases = False
            with WaitCursor():
                resp = urlopen('https://api.github.com/repos/sevaa/dwex/releases')
                if resp.getcode() == 200:
                    releases = json.loads(resp.read())
            if releases and len(releases) > 0:
                max_ver = max(tuple(int(v) for v in r['tag_name'].split('.')) for r in releases)
                max_tag = '.'.join(str(i) for i in max_ver)
                if max_ver > version:
                    s = "DWARF Explorer v." + max_tag + " is out. Use \"pip install --upgrade dwex\" to update."
                    # TODO: not only pip
                else: 
                    s = "You have the latest version."
                QMessageBox(QMessageBox.Icon.Information, "DWARF Explorer", s, QMessageBox.StandardButton.Ok, self).show()
        except:
            pass

    def on_exit(self):
        self.destroy()
        QApplication.quit()

    # Checkmark toggling is handled by the framework
    def on_view_prefix(self, checked):
        self.prefix = checked
        self.sett.setValue('General/Prefix', self.prefix)
        if self.tree_model:
            self.tree_model.set_prefix(checked)

        if self.die_model:
            self.die_model.set_prefix(checked)
            self.refresh_details()

    # Checkmark toggling is handled by the framework
    def on_view_lowlevel(self, checked):   
        self.lowlevel = checked
        self.sett.setValue('General/LowLevel', self.lowlevel)
        if self.die_model:
            new_sel = self.die_model.set_lowlevel(checked, self.die_table.currentIndex())
            if new_sel:
                self.die_table.setCurrentIndex(new_sel)

    def on_view_hex(self, checked):        
        self.hex = checked
        self.sett.setValue('General/Hex', self.hex)
        if self.die_model:
            self.die_model.set_hex(checked)
            self.refresh_details()

    def on_view_regnames(self, checked):        
        self.dwarfregnames = checked
        self.sett.setValue('General/DWARFRegNames', self.dwarfregnames)
        if self.die_model:
            self.die_model.set_regnames(checked)
            self.refresh_details()            

    def on_sortcus(self, checked):
        self.sortcus = checked
        self.sett.setValue('General/SortCUs', self.sortcus)
        if self.tree_model:
            sel = self.the_tree.currentIndex()
            sel = self.tree_model.set_sortcus(checked, sel) # This will reload the tree
            if sel:
                self.the_tree.setCurrentIndex(sel)

    def on_sortdies(self, checked):
        self.sortdies = checked
        self.sett.setValue('General/SortDIEs', self.sortdies)
        if self.tree_model:
            #Throw away everything we had cached so far
            sel = self.tree_model.set_sortdies(checked)
            #This invalidates the navigation
            self.back_menuitem.setEnabled(False)
            self.back_tbitem.setEnabled(False)
            self.forward_menuitem.setEnabled(False)
            self.forward_tbitem.setEnabled(False)
            self.followref_menuitem.setEnabled(False)
            self.followref_tbitem.setEnabled(False)
            # Navigation stack - empty
            self.navhistory = []
            self.navpos = -1
            if sel:
                self.the_tree.setCurrentIndex(sel)

    # Tree highlighting business

    def manage_hlnavigation(self, b = None):
        if b is None:
            b = self.tree_model.has_any_highlights()
        self.prevhl_menuitem.setEnabled(b)
        self.nexthl_menuitem.setEnabled(b)
        self.prevhl_tbitem.setEnabled(b)
        self.nexthl_tbitem.setEnabled(b)

    def highlight_off(self, key):
        self.tree_model.remove_highlight(key)
        self.manage_hlnavigation()

    def on_highlight_code(self):
        if self.tree_model.has_highlight(1):
            self.highlight_off(1)
        else:
            self.tree_model.add_highlight(1, has_code_location)        
            self.manage_hlnavigation(True)

    def on_highlight_substring(self):
        if self.tree_model.has_highlight(2):
            self.highlight_off(2)
        else:
            r = QInputDialog.getText(self, 'Highlight', 'Highlight DIEs with substring:')
            if r[1] and r[0]:
                s = r[0].lower()
                self.tree_model.add_highlight(2, lambda die:self.findbytext(die, s))
                self.manage_hlnavigation(True)
            else:
                self.highlightsubstring_menuitem.setChecked(False)

    def on_highlight_condition(self):
        if self.tree_model.has_highlight(3):
            self.highlight_off(3)
        else:
            dlg = ScriptDlg(self, self.sample_die())
            if dlg.exec() == QDialog.DialogCode.Accepted:
                cond = dlg.cond
                self.tree_model.add_highlight(3, lambda die: self.eval_user_condition(cond, die))
                self.manage_hlnavigation(True)
            else:
                self.highlightcondition_menuitem.setChecked(False)
            # Accepted with blank or bogus expression is not supported

    def on_highlight_nothing(self):
        self.highlightcode_menuitem.setChecked(False)
        self.highlightsubstring_menuitem.setChecked(False)
        self.highlightcondition_menuitem.setChecked(False)
        self.manage_hlnavigation(False)
        if self.tree_model:
            self.tree_model.clear_highlight()

    def on_nexthl(self):
        index = self.tree_model.find(self.the_tree.currentIndex(), self.tree_model.is_highlighted, False)
        if index:
            self.the_tree.setCurrentIndex(index)

    def on_prevhl(self):
        index = self.tree_model.find_back(self.the_tree.currentIndex(), self.tree_model.is_highlighted, False)
        if index:
            self.the_tree.setCurrentIndex(index)

    def on_cuproperties(self):
        die = self.the_tree.currentIndex().internalPointer()
        if die:
            cu = die.cu
            ver = cu['version']
            if ver > 1:
                props = (ver, cu['unit_length'], cu['debug_abbrev_offset'], cu['address_size'])
                s = "DWARF version:\t%d\nLength:\t%d\nAbbrev table offset: 0x%x\nAddress size:\t%d" % props
            else:
                props = (ver, cu['address_size'])
                s = "DWARF version:\t%d\nAddress size:\t%d" % props
            t = "CU at 0x%x" % cu.cu_offset
            QMessageBox(QMessageBox.Icon.Information, t, s, QMessageBox.StandardButton.Ok, self).show()

    def on_copy(self, v):
        cb = QApplication.clipboard()
        cb.clear()
        cb.setText(v)

    def on_copyvalue(self):
        t = self.details_table if self.details_table.hasFocus() and self.details_table.model() else self.die_table
        m = t.model()
        self.on_copy(m.data(t.currentIndex(), Qt.ItemDataRole.DisplayRole) or "")

    def on_copyline(self):
        t = self.details_table if self.details_table.hasFocus() else self.die_table
        m = t.model()
        row = t.currentIndex().row()
        line = "\t".join(str(m.data(m.index(row, c, QModelIndex()), Qt.ItemDataRole.DisplayRole) or "")
            for c in range(0, m.columnCount(QModelIndex())))
        self.on_copy(line)

    def on_copytable(self):
        t = self.details_table if self.details_table.hasFocus() else self.die_table
        m = t.model()
        table_text = "\n".join(
                "\t".join(str(m.data(m.index(r, c, QModelIndex()), Qt.ItemDataRole.DisplayRole)  or "")
                for c in range(0, m.columnCount(QModelIndex())))
            for r in range(0, m.rowCount(QModelIndex())))
        self.on_copy(table_text)

    ##################################################################

    def on_localsat(self):
        dlg = LocalsDlg(self, self.dwarfinfo, self.prefix, self.dwarfregnames, self.hex)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.selected_die:
             self.the_tree.setCurrentIndex(self.tree_model.index_for_die(dlg.selected_die))

    def on_funcmap(self):
        th = GatherFuncsThread(self, self.dwarfinfo)
        def done():
            if not pd.wasCanceled():
                pd.close()

            if th.funcs:
                dlg = FuncMapDlg(self, self.hex, th.funcs)
                if dlg.exec() == QDialog.DialogCode.Accepted and dlg.selected_die:
                    self.the_tree.setCurrentIndex(self.tree_model.index_for_die(dlg.selected_die))
            elif th.exc:
                print(th.exc)

        last_CU = self.dwarfinfo._unsorted_CUs[-1]
        pd = QProgressDialog("Gathering functions...", "Cancel", 0, last_CU.cu_offset + last_CU.size, self, Qt.WindowType.Dialog)
        pd.canceled.connect(th.cancel)
        pd.show()
        th.progress.connect(pd.setValue)
        th.finished.connect(done)
        th.start() # Will continue in done

    def on_aranges(self):
        from elftools.common.exceptions import ELFParseError
        try:
            ara = self.dwarfinfo.get_aranges()
        except ELFParseError: # Catching the IAR < 9.30 aranges misalignment issue
            self.show_warning("The aranges section in this binary is corrupt.")
            return

        if ara:
            dlg = ArangesDlg(self, ara, self.dwarfinfo, self.hex)
            if dlg.exec() == QDialog.DialogCode.Accepted and dlg.selected_cu_offset is not None:
                di = self.dwarfinfo
                i = bisect_left(di._CU_offsets, dlg.selected_cu_offset)
                if i < len(di._CU_offsets) and di._CU_offsets[i] == dlg.selected_cu_offset:
                    die = di._unsorted_CUs[i].get_top_DIE()
                    self.the_tree.setCurrentIndex(self.tree_model.index_for_die(die))
        else:
            self.show_warning("This binary does not have an aranges section.")
            
    def on_frames(self):
        try:
            entries = get_di_frames(self.dwarfinfo)
            if entries:
                FramesDlg(self, entries, self.dwarfinfo, self.dwarfregnames, self.hex).exec()
                # TODO: navigate to function
            else:
                self.show_warning("This binary does not have neither an eh_frames section nor a debug_frames section.")
        except KeyError: # 1761
            self.show_warning("Error parsing the frames section in this binary. Please report to the tech support: menu/Help/Report an issue.")

            
    def on_unwind(self):
        if self.dwarfinfo._unwind_sec:
            UnwindDlg(self, self.dwarfinfo._unwind_sec, self.dwarfinfo, self.dwarfregnames, self.hex).exec()
            # TODO: navigate to function
        elif self.dwarfinfo._has_exec:
            self.show_warning("Neither this binary/slice nor the companion executable has an unwind_info section.")
        else: # TODO: distinguish .o files where the section is named differently
            self.show_warning("This binary/slice does not have an unwind_info section, but the corresponding executable might. Use File/Load companion... to find and load one.")

    # If the details pane has data - reload that
    def refresh_details(self):
        index = self.die_table.currentIndex()
        if index.isValid():
            details_model = self.die_model.get_attribute_details(index)
            if details_model:
                self.details_table.setModel(details_model)
                self.details_table.resizeColumnsToContents()
        self.die_table.resizeColumnsToContents()

    def on_issue(self):
        QDesktopServices.openUrl(QUrl('https://github.com/sevaa/dwex/issues/new'))

    def on_homepage(self):
        QDesktopServices.openUrl(QUrl('https://github.com/sevaa/dwex'))

    # All purpose debug hook
    def on_debug(self):
        pass

    def show_warning(self, s):
        QMessageBox(QMessageBox.Icon.Warning, "DWARF Explorer", s, QMessageBox.StandardButton.Ok, self).show()

    def expr_formatter(self):
        return self.die_model.expr_formatter

def on_exception(exctype, exc, tb):
    if isinstance(exc, MemoryError):
        app = QApplication.instance()
        app.win.destroy()
        app.win = None
        QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer", "Out of memory. DWARF Explorer will now close. Sorry.",
            QMessageBox.StandardButton.Ok, None).show()
        sys.exit(1)
    elif isinstance(exc, Exception):
        from .crash import report_crash
        report_crash(exc, exc.__traceback__, version)
        try:
            global the_app
            if the_app and the_app.win and the_app.win.sett:
                the_app.win.sett.setValue("Crashed", True)
        except Exception:
            pass
        sys.excepthook = on_exception.prev_exchook
        sys.exit(1)
    elif on_exception.prev_exchook:
        on_exception.prev_exchook(exctype, exc, tb)

class TheApp(QApplication):
    def __init__(self):
        super().__init__([])
        self.win = None

    def notify(self, o, evt):
        if evt.type() == QEvent.Type.MouseButtonPress and isinstance(o, QWindow) and hasattr(evt, "button"):
            b = evt.button()
            if b == Qt.MouseButton.BackButton:
                self.win.on_nav(1)
            elif b == Qt.MouseButton.ForwardButton:
                self.win.on_nav(-1)
        return QApplication.notify(self, o, evt)
    
    def start(self):
        self.win = TheWindow()
        self.exec()

def main():
    under_debugger = hasattr(sys, 'gettrace') and sys.gettrace() or hasattr(sys, 'monitoring') and sys.monitoring.get_tool(sys.monitoring.DEBUGGER_ID) # Lame way to detect a debugger
    if not under_debugger: 
        on_exception.prev_exchook = sys.excepthook
        sys.excepthook = on_exception

    from .patch import monkeypatch
    monkeypatch()

    global the_app
    the_app = TheApp()
    the_app.start()

# For running via "python -m dwex"
# Running this file directly won't work, it relies on being in a module
if __name__ == "__main__":
    main()