import sys, os, io, platform
from PyQt5.QtCore import Qt, QModelIndex, QSettings, QUrl
from PyQt5.QtGui import QFontMetrics, QKeySequence, QDesktopServices
from PyQt5.QtWidgets import *
from .die import DIETableModel
from .formats import read_dwarf
from .tree import DWARFTreeModel, has_code_location
from .scriptdlg import ScriptDlg
from .ui import setup_ui

version=(0,56)

# TODO:
# Autotest on corpus
# Test back-forward mouse buttons
# On MacOS, start without a main window, instead show the Open dialog

#-----------------------------------------------------------------
# The one and only main window class
# Pretty much DWARF unaware, all the DWARF visualization logic is in tree.py and die.py
#-----------------------------------------------------------------

class TheWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.in_tree_nav = False
        self.font_metrics = QFontMetrics(QApplication.font())

        self.load_settings()
        setup_ui(self)
        self.setAcceptDrops(True)

        # The data model placeholders - to be populated once we read a file
        self.tree_model = None # Recreated between files
        self.die_model = None # Reused between DIEs

        self.findcondition = None

        self.show()

        # Command line: if can't open, print the error to console
        # On Mac/Linux, the user will see it. On Windows, they won't.
        if len(sys.argv) > 1:
            try:
                if self.open_file(sys.argv[1]) is None:
                    print("The file contains no DWARF information, or it is in an unsupported format.")
            except Exception as exc:
                print(format(exc))

    def load_settings(self):
        self.sett = QSettings('Seva', 'DWARFExplorer')
        self.prefix = self.sett.value('General/Prefix', False, type=bool)
        self.lowlevel = self.sett.value('General/LowLevel', False, type=bool)
        self.hex = self.sett.value('General/Hex', False, type=bool)
        self.mru = []
        for i in range(0, 10):
            f = self.sett.value("General/MRU%d" % i, False)
            if f:
                arch = self.sett.value("General/MRUArch%d" % i, None)
                fa = (f,) if arch is None else (f,arch) 
                self.mru.append(fa)        

    ###################################################################
    # Done with init, now file stuff
    ###################################################################

    # Callback for the Mach-O fat binary opening logic
    # Taking a cue from Hopper or IDA, we parse only one slice at a time
    def resolve_arch(self, arches):
        r = QInputDialog.getItem(self, 'Mach-O Fat Binary', 'Choose an architecture:', arches, 0, False, Qt.WindowType.Dialog)
        return arches.index(r[0]) if r[1] else None

    # Can throw an exception
    # Returns None if it doesn't seem to contain DWARF
    # False if the user cancelled
    # True if the DWARF tree was loaded
    def open_file(self, filename, arch = None):
        self.start_wait()
        try:
            di = read_dwarf(filename, self.resolve_arch if arch is None else lambda arches: arches.index(arch))
            if not di: # Covers both False and None
                return di

            # Some cached top level stuff
            # Notably, iter_CUs doesn't cache
            di._ranges = None # Loaded on first use
            def decorate_cu(cu, i):
                cu._i = i
                cu._lineprogram = None
                return cu
            di._CUs = [decorate_cu(cu, i) for (i, cu) in enumerate(di.iter_CUs())] # We'll need them first thing, might as well load here
            if not len(di._CUs):
                return None # Weird, but saw it once - debug sections present, but no CUs
            di._locparser = None # Created on first use

            self.tree_model = DWARFTreeModel(di, self.prefix)
            self.the_tree.setModel(self.tree_model)
            self.the_tree.selectionModel().currentChanged.connect(self.on_tree_selection)
            s = os.path.basename(filename)
            if arch is not None:
                s += ' (' + arch + ')'
            self.setWindowTitle("DWARF Explorer - " + s)
            self.back_menuitem.setEnabled(False)
            self.forward_menuitem.setEnabled(False)
            self.followref_menuitem.setEnabled(False)
            self.highlightcode_menuitem.setEnabled(True)
            self.highlightnothing_menuitem.setEnabled(True)
            self.copy_menuitem.setEnabled(False)
            self.copyline_menuitem.setEnabled(False)
            self.copytable_menuitem.setEnabled(False)
            self.findbycondition_menuitem.setEnabled(True)
            self.find_menuitem.setEnabled(True)
            # Navigation stack - empty
            self.navhistory = []
            self.navpos = -1
            self.save_filename_in_mru(filename, di._fat_arch if '_fat_arch' in dir(di) and di._fat_arch else None)
            return True
        finally:
            self.end_wait()

    def save_mru(self):
        for i, fa in enumerate(self.mru):
            self.sett.setValue("General/MRU%d" % i, fa[0])    
            if len(fa) > 1:
                self.sett.setValue("General/MRUArch%d" % i, fa[1])
            else:
                self.sett.remove("General/MRUArch%d" % i)

    # Open a file, display an error if failure
    def open_file_interactive(self, filename, arch = None):
        try:
            if self.open_file(filename, arch) is None:
                QMessageBox(QMessageBox.Icon.Warning, "DWARF Explorer",
                    "The file contains no DWARF information, or it is in an unsupported format.",
                    QMessageBox.Ok, self).show()
        except Exception as exc:
            QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer",
                "Error opening the file:\n\n" + format(exc),
                QMessageBox.Ok, self).show()

    # TODO: list the extensions for the open file dialog?
    def on_open(self):
        dir = os.path.dirname(self.mru[0][0]) if len(self.mru) > 0 else ''
        filename = QFileDialog.getOpenFileName(self, None, dir)
        if filename[0]:
            self.open_file_interactive(os.path.normpath(filename[0]))

    def populate_mru_menu(self):
        class MRUHandler(object):
            def __init__(self, fa, win):
                object.__init__(self)
                self.fa = fa
                self.win = win
            def __call__(self):
                self.win.open_file_interactive(*self.fa)

        for i, fa in enumerate(self.mru):
            s = fa[0]
            if len(fa) > 1:
                s += ' (' + fa[1] + ')'
            self.mru_menu.addAction(s).triggered.connect(MRUHandler(fa, self))

    def save_filename_in_mru(self, filename, arch = None):
        mru_record = (filename,) if arch is None else (filename, arch)
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

    # File drag/drop handling - equivalent to open
    def dragEnterEvent(self, evt):
        if evt.mimeData() and evt.mimeData().hasUrls() and len(evt.mimeData().urls()) == 1:
            evt.accept()

    def dropEvent(self, evt):
        self.open_file_interactive(os.path.normpath(evt.mimeData().urls()[0].toLocalFile()))               

    #############################################################
    # Done with file stuff, now tree navigation
    #############################################################     

    # Index is a tree index - the DIE is the data object within
    def display_die(self, index):
        die = index.internalPointer()
        die_table = self.die_table
        if not self.die_model:
            self.die_model = DIETableModel(die, self.prefix, self.lowlevel, self.hex)
            die_table.setModel(self.die_model)
            die_table.selectionModel().currentChanged.connect(self.on_attribute_selection)
        else:
            self.die_model.display_DIE(die)
        self.die_table.resizeColumnsToContents()
        self.details_table.setModel(None)
        self.followref_menuitem.setEnabled(False)
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
            self.navhistory[0:self.navpos] = [navitem]
            self.navpos = 0
            self.back_menuitem.setEnabled(len(self.navhistory) > 1)
            self.forward_menuitem.setEnabled(False)
        self.display_die(index) # Will clear the selection in the attribute table

    # Selection changed in the DIE table - either user or program
    def on_attribute_selection(self, index, prev = None):
        if index.isValid():
            details_model = self.die_model.get_attribute_details(index)
            self.details_table.setModel(details_model)
            if details_model is not None:
                self.details_table.resizeColumnsToContents()
            self.followref_menuitem.setEnabled(self.die_model.ref_target(index) is not None)
            self.copy_menuitem.setEnabled(True)
            self.copyline_menuitem.setEnabled(True)
            self.copytable_menuitem.setEnabled(True)
        else: # Selected nothing
            self.details_table.setModel(None)
            self.copy_menuitem.setEnabled(False)
            self.copyline_menuitem.setEnabled(False)
            self.copytable_menuitem.setEnabled(False)            
            self.followref_menuitem.setEnabled(False)


    def on_attribute_dclick(self, index):
        self.followref(index)

    # For both back and forward, delta=1 for back, -1 for forward
    def on_nav(self, delta):
        self.navpos += delta
        navitem = self.navhistory[self.navpos]
        tree_index = self.tree_model.index_for_navitem(navitem)
        self.in_tree_nav = True
        self.the_tree.setCurrentIndex(tree_index) # Causes on_tree_selection internally
        self.in_tree_nav = False
        self.back_menuitem.setEnabled(self.navpos < len(self.navhistory) - 1)
        self.forward_menuitem.setEnabled(self.navpos > 0)

    def followref(self, index = None):
        self.start_wait() # TODO: only show the wait cursor if it's indeed time consuming
        if index is None:
            index = self.die_table.currentIndex()
        navitem = self.die_model.ref_target(index)  # Retrieve the ref target from the DIE model...
        if navitem:
            target_tree_index = self.tree_model.index_for_navitem(navitem) # ...and feed it to the tree model.
            self.the_tree.setCurrentIndex(target_tree_index) # Calls on_tree_selection internally
        self.end_wait()

    # Called for double-click on a reference type attribute, and via the menu
    def on_followref(self):
        self.followref()

    # Back-forward mouse buttons are shortcuts for back/forward navigation
    # Qt docs claim capturing is not necessary
    def mouseReleaseEvent(self, evt):
        QMainWindow.mouseReleaseEvent(self, evt)
        b = evt.button()
        if b == Qt.MouseButton.BackButton:
            self.on_nav(1)
        elif b == Qt.MouseButton.ForwardButton:
            self.on_nav(-1)
        

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
            return eval(cond, {'die' : die})
        except Exception as exc:
            print("Error in user condition: %s" % format(exc))
            return False

    def on_find(self):
        r = QInputDialog.getText(self, 'Find', 'Find what:')
        if r[1] and r[0]:
            s = r[0].lower()
            self.findcondition = lambda die: self.findbytext(die, s)
            self.findnext_menuitem.setEnabled(True)
            self.on_findnext()

    def on_findbycondition(self):
        dlg = ScriptDlg(self)
        if dlg.exec() == QDialog.Accepted:
            cond = dlg.cond
            self.findcondition = lambda die: self.eval_user_condition(cond, die)
            self.findnext_menuitem.setEnabled(True)
            self.on_findnext()

    def on_findnext(self):
        index = self.tree_model.find(self.the_tree.currentIndex(), self.findcondition)
        if index:
            self.the_tree.setCurrentIndex(index)

    ##########################################################################
    ##########################################################################

    def on_about(self):
        QMessageBox(QMessageBox.Icon.Information, "About...", "DWARF Explorer v." + '.'.join(str(v) for v in version) + "\n\nSeva Alekseyev, 2020\nsevaa@sprynet.com\n\ngithub.com/sevaa/dwex",
            QMessageBox.Ok, self).show()

    def on_updatecheck(self):
        from urllib.request import urlopen
        import json
        try:
            self.start_wait()
            resp = urlopen('https://api.github.com/repos/sevaa/dwex/releases')
            if resp.getcode() == 200:
                releases = resp.read()
                self.end_wait()
                releases = json.loads(releases)
                if len(releases) > 0:
                    max_ver = max(tuple(int(v) for v in r['tag_name'].split('.')) for r in releases)
                    max_tag = '.'.join(str(i) for i in max_ver)
                    if max_ver > version:
                        s = "DWARF Explorer v." + max_tag + " is out. Use \"pip install --upgrade dwex\" to update."
                    else: 
                        s = "You have the latest version."
                    QMessageBox(QMessageBox.Icon.Information, "DWARF Explorer", s, QMessageBox.Ok, self).show()
        except:
            self.end_wait()

    def on_exit(self):
        self.destroy()

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
        self.sett.setValue('General/Hex', self.lowlevel)
        if self.die_model:
            self.die_model.set_hex(checked)
            self.refresh_details()        

    def on_highlight_code(self):
        self.highlightcode_menuitem.setChecked(True)
        self.tree_model.highlight(has_code_location)

    def on_highlight_nothing(self):
        self.highlightcode_menuitem.setChecked(False)
        self.tree_model.highlight(None)

    def on_cuproperties(self):
        cu = self.the_tree.currentIndex().internalPointer().cu
        props = (cu['version'], cu['unit_length'], cu['debug_abbrev_offset'], cu['address_size'])
        s = "DWARF version:\t%d\nLength:\t%d\nAbbrev table offset: 0x%x\nAddress size:\t%d" % props
        t = "CU at 0x%x" % cu.cu_offset
        QMessageBox(QMessageBox.Icon.Information, t, s, QMessageBox.Ok, self).show()

    def on_copy(self, v):
        cb = QApplication.clipboard()
        cb.clear()
        cb.setText(v)

    def on_copyvalue(self):
        t = self.details_table if self.details_table.hasFocus() else self.die_table
        m = t.model()
        self.on_copy(m.data(t.currentIndex(), Qt.DisplayRole))

    def on_copyline(self):
        t = self.details_table if self.details_table.hasFocus() else self.die_table
        m = t.model()
        row = t.currentIndex().row()
        line = "\t".join(m.data(m.index(row, c, QModelIndex()), Qt.DisplayRole)
            for c in range(0, m.columnCount(QModelIndex())))
        self.on_copy(line)

    def on_copytable(self):
        t = self.details_table if self.details_table.hasFocus() else self.die_table
        m = t.model()
        table_text = "\n".join(
                "\t".join(m.data(m.index(r, c, QModelIndex()), Qt.DisplayRole)
                for c in range(0, m.columnCount(QModelIndex())))
            for r in range(0, m.rowCount(QModelIndex())))
        self.on_copy(table_text)

    # If the details pane has data - reload that
    def refresh_details(self):
        index = self.die_table.currentIndex()
        if index.isValid():
            details_model = self.die_model.get_attribute_details(index)
            if details_model:
                self.details_table.setModel(details_model)
                self.details_table.resizeColumnsToContents()
        self.die_table.resizeColumnsToContents()

    def on_homepage(self):
        QDesktopServices.openUrl(QUrl('https://github.com/sevaa/dwex'))

    # Doesn't quite work for the delay on tree expansion :(
    def start_wait(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)

    def end_wait(self):
        QApplication.restoreOverrideCursor()

def on_exception(exctype, exc, tb):
    from .crash import report_crash
    report_crash(exc, tb, version)
    sys.excepthook = on_exception.prev_exchook
    sys.exit(1)

def main():     
    if sys.settrace is None: # Lame way to detect a debugger
        on_exception.prev_exchook = sys.excepthook
        sys.excepthook = on_exception

    the_app = QApplication([])
    win = TheWindow()
    the_app.exec_()        

# For running via "python -m dwex"
# Running this file directly won't work, it relies on being in a module
if __name__ == "__main__":
    main()