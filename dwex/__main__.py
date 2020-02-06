import sys, os, io, platform
from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex, QSettings, QUrl
from PyQt5.QtGui import QFontMetrics, QKeySequence, QDesktopServices
from PyQt5.QtWidgets import *
from .die import DIETableModel
from .formats import read_dwarf
from .tree import DWARFTreeModel, has_code_location
from .scriptdlg import ScriptDlg

version=(0,53)

# TODO:
# Low level raw bytes for expressions in location lists
# Autotest on corpus
# What else is section_offset?
# const_value as FORM_block1: an array of 4 bytes, found in iOS/4.69.8/ARMv7/DecompItem.mm 
# Test back-forward mouse buttons
# On MacOS, start without a main window, instead show the Open dialog


#-----------------------------------------------------------------
# The one and only main window class
# Pretty much DWARF unaware, all the DWARF visualization logic is in tree.py and die.py
#-----------------------------------------------------------------

class TheWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.wait_level = 0
        self.font_metrics = QFontMetrics(QApplication.font())

        self.load_settings()
        self.setup_menu()
        self.setup_ui()
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

    def setup_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        open_menuitem = file_menu.addAction("Open...")
        open_menuitem.setShortcut(QKeySequence.Open)
        open_menuitem.triggered.connect(self.on_open)
        self.mru_menu = file_menu.addMenu("Recent files")
        if len(self.mru):
            self.populate_mru_menu()
        else:
            self.mru_menu.setEnabled(False)
        exit_menuitem = file_menu.addAction("E&xit")
        exit_menuitem.setMenuRole(QAction.QuitRole)
        exit_menuitem.setShortcut(QKeySequence.Quit)
        exit_menuitem.triggered.connect(self.on_exit)
        #########
        view_menu = menu.addMenu("View")
        self.prefix_menuitem = view_menu.addAction("DWARF prefix")
        self.prefix_menuitem.setCheckable(True)
        self.prefix_menuitem.setChecked(self.prefix)
        self.prefix_menuitem.triggered.connect(self.on_view_prefix)
        self.lowlevel_menuitem = view_menu.addAction("Low level")
        self.lowlevel_menuitem.setCheckable(True)
        self.lowlevel_menuitem.setChecked(self.lowlevel)
        self.lowlevel_menuitem.triggered.connect(self.on_view_lowlevel)
        self.hex_menuitem = view_menu.addAction("Hexadecimal")
        self.hex_menuitem.setCheckable(True)
        self.hex_menuitem.setChecked(self.hex)
        self.hex_menuitem.triggered.connect(self.on_view_hex)
        view_menu.addSeparator()
        self.highlightcode_menuitem = view_menu.addAction("Highlight code")
        self.highlightcode_menuitem.setCheckable(True)
        self.highlightcode_menuitem.setEnabled(False)
        self.highlightcode_menuitem.triggered.connect(self.on_highlight_code)
        self.highlightnothing_menuitem = view_menu.addAction("Remove highlighting")
        self.highlightnothing_menuitem.setEnabled(False)
        self.highlightnothing_menuitem.triggered.connect(self.on_highlight_nothing)
        view_menu.addSeparator()
        self.cuproperties_menuitem = view_menu.addAction("CU properties...")
        self.cuproperties_menuitem.setEnabled(False)
        self.cuproperties_menuitem.triggered.connect(self.on_cuproperties)
        #########
        edit_menu = menu.addMenu("Edit")
        self.copy_menuitem = edit_menu.addAction("Copy value")
        self.copy_menuitem.setShortcut(QKeySequence.Copy)
        self.copy_menuitem.setEnabled(False)
        self.copy_menuitem.triggered.connect(self.on_copyvalue)
        self.copyline_menuitem = edit_menu.addAction("Copy line")
        self.copyline_menuitem.setEnabled(False)
        self.copyline_menuitem.triggered.connect(self.on_copyline)        
        self.copytable_menuitem = edit_menu.addAction("Copy table")
        self.copytable_menuitem.setEnabled(False)
        self.copytable_menuitem.triggered.connect(self.on_copytable)  
        #########
        nav_menu = menu.addMenu("Navigate")
        self.back_menuitem = nav_menu.addAction("Back")
        self.back_menuitem.setShortcut(QKeySequence.Back)
        self.back_menuitem.setEnabled(False);
        self.back_menuitem.triggered.connect(lambda: self.on_nav(1))
        self.forward_menuitem = nav_menu.addAction("Forward")
        self.forward_menuitem.setShortcut(QKeySequence.Forward)
        self.forward_menuitem.setEnabled(False);
        self.forward_menuitem.triggered.connect(lambda: self.on_nav(-1))
        self.followref_menuitem = nav_menu.addAction("Follow the ref")
        self.followref_menuitem.setEnabled(False);
        self.followref_menuitem.triggered.connect(self.on_followref)        
        nav_menu.addSeparator()
        self.find_menuitem = nav_menu.addAction("Find...")
        self.find_menuitem.setEnabled(False)
        self.find_menuitem.setShortcut(QKeySequence.Find)
        self.find_menuitem.triggered.connect(self.on_find)
        self.findbycondition_menuitem = nav_menu.addAction("Find by condition...")
        self.findbycondition_menuitem.setEnabled(False)
        self.findbycondition_menuitem.triggered.connect(self.on_findbycondition)
        self.findnext_menuitem = nav_menu.addAction("Find next")
        self.findnext_menuitem.setEnabled(False)
        self.findnext_menuitem.setShortcut(QKeySequence.FindNext)
        self.findnext_menuitem.triggered.connect(self.on_findnext)
        ########
        help_menu = menu.addMenu("Help")
        about_menuitem = help_menu.addAction("About...")
        about_menuitem.setMenuRole(QAction.AboutRole)
        about_menuitem.triggered.connect(self.on_about) 
        help_menu.addAction('Check for updates...').triggered.connect(self.on_updatecheck)
        help_menu.addAction('Homepage').triggered.connect(self.on_homepage)

    def setup_ui(self):
        # Set up the left pane and the right pane
        tree = self.the_tree = QTreeView()
        tree.header().hide()
        tree.setUniformRowHeights(True)
        tree.clicked.connect(self.on_tree_selection)
        
        rpane = QSplitter(Qt.Orientation.Vertical)
        die_table = self.die_table = QTableView()
        die_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        die_table.clicked.connect(self.on_attribute_selection)
        die_table.doubleClicked.connect(self.on_attribute_dclick)
        rpane.addWidget(die_table)

        details_table = self.details_table = QTableView()
        details_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        rpane.addWidget(details_table)
        # All the resizing goes into the bottom pane
        rpane.setStretchFactor(0, 0)
        rpane.setStretchFactor(1, 1)

        spl = QSplitter()
        spl.addWidget(self.the_tree)
        spl.addWidget(rpane)
        # All the resizing goes into the right pane by default
        spl.setStretchFactor(0, 0)
        spl.setStretchFactor(1, 1) 
        self.setCentralWidget(spl)

        self.setWindowTitle("DWARF Explorer")
        self.resize(self.font_metrics.averageCharWidth() * 250, self.font_metrics.height() * 60)


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
            di._locparser = None # Created on first use

            self.tree_model = DWARFTreeModel(di, self.prefix)
            self.the_tree.setModel(self.tree_model)
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
        else:
            self.die_model.display_DIE(die)
        self.die_table.resizeColumnsToContents()
        self.details_table.setModel(None)
        self.followref_menuitem.setEnabled(False)
        self.cuproperties_menuitem.setEnabled(True)
        self.die_table.setCurrentIndex(QModelIndex())

        #TODO: resize the attribute table dynamically
        #attr_count = self.die_model.rowCount(None)
        #die_table.resize(die_table.size().width(),
        #    die_table.rowViewportPosition(attr_count-1) + 
        #        die_table.rowHeight(attr_count-1) +
        #        die_table.horizontalHeader().size().height() + 1 + attr_count)
        #self.rpane_layout.update()

    # Invoked for ref follow, too
    # But not for back-forward
    def on_tree_selection(self, index):
        navitem = self.tree_model.get_navitem(index)
        self.navhistory[0:self.navpos] = [navitem]
        self.navpos = 0
        self.back_menuitem.setEnabled(len(self.navhistory) > 1)
        self.forward_menuitem.setEnabled(False)
        self.display_die(index)
        self.die_table.setCurrentIndex(QModelIndex())
        self.copy_menuitem.setEnabled(False)
        self.copyline_menuitem.setEnabled(False)
        self.copytable_menuitem.setEnabled(False)

    def on_attribute_selection(self, index):
        details_model = self.die_model.get_attribute_details(index)
        self.details_table.setModel(details_model)
        if details_model is not None:
            self.details_table.resizeColumnsToContents()
        self.followref_menuitem.setEnabled(self.die_model.ref_target(index) is not None)
        self.copy_menuitem.setEnabled(True)
        self.copyline_menuitem.setEnabled(True)
        self.copytable_menuitem.setEnabled(True)        

    def on_attribute_dclick(self, index):
        self.on_followref(index)

    # For both back and forward
    def on_nav(self, delta):
        self.navpos += delta
        navitem = self.navhistory[self.navpos]
        tree_index = self.tree_model.index_for_navitem(navitem)
        self.the_tree.setCurrentIndex(tree_index)
        self.display_die(tree_index)
        self.back_menuitem.setEnabled(self.navpos < len(self.navhistory) - 1)
        self.forward_menuitem.setEnabled(self.navpos > 0)

    # Called for double-click on a reference type attribute, and via the menu
    def on_followref(self, index = None):
        self.start_wait() # TODO: only show the wait cursor if it's indeed time consuming
        if index is None:
            index = self.die_table.getCurrentIndex()
        navitem = self.die_model.ref_target(index)  # Retrieve the ref target from the DIE model...
        if navitem:
            target_tree_index = self.tree_model.index_for_navitem(navitem) # ...and feed it to the tree model.
            self.the_tree.setCurrentIndex(target_tree_index)
            # Qt doesn't raise the notification by itself
            self.on_tree_selection(target_tree_index)
        self.end_wait()

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
            self.on_tree_selection(index)

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
                    max_tag = max(r['tag_name'] for r in releases)
                    max_ver = tuple(int(v) for v in max_tag.split('.'))
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
            self.die_model.set_lowlevel(checked)
            self.refresh_details()

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
        if self.wait_level == 0:
            self.setCursor(Qt.WaitCursor)
        self.wait_level += 1

    def end_wait(self):
        if self.wait_level > 0:
            self.wait_level -= 1
        if self.wait_level == 0:
            self.setCursor(Qt.ArrowCursor)

def main():     
    if sys.settrace is None: # Lame way to detect a debugger
        try:
            the_app = QApplication([])
            the_window = TheWindow()
            the_app.exec_()        
        except Exception as exc:
            from .crash import report_crash
            report_crash(exc, version)
    else: # Running under a debugger - surface the uncaught exceptions
        the_app = QApplication([])
        the_window = TheWindow()
        the_app.exec_()        

# For running via "python -m dwex"
if __name__ == "__main__":
    main()