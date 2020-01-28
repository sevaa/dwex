import sys, os, io, struct
from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex, QSettings
from PyQt5.QtGui import QFontMetrics 
from PyQt5.QtWidgets import *
from die import DIETableModel
from formats import read_dwarf
from tree import DWARFTreeModel

#-----------------------------------------------------------------
#  The one and only main window class
#-----------------------------------------------------------------

class TheWindow(QMainWindow):
    def __init__(self):
        self.sett = QSettings('Seva', 'DWARFExplorer')
        self.prefix = self.sett.value('General/Prefix', False, type=bool)
        self.mru = []
        for i in range(0, 10):
            s = self.sett.value("General/MRU%d" % i, False)
            if s:
                self.mru.append(s)
        QMainWindow.__init__(self)
        self.wait_level = 0
        font_metrics = self.font_metrics = QFontMetrics(QApplication.font())

        # Set up the menu
        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        file_menu.addAction("Open...").triggered.connect(self.on_open)
        if len(self.mru):
            mru_menu = file_menu.addMenu("Recent files")
            self.populate_mru_menu(mru_menu)
        file_menu.addAction("E&xit").triggered.connect(self.on_exit)
        view_menu = menu.addMenu("View")
        self.prefix_menuitem = view_menu.addAction("DWARF prefix")
        self.prefix_menuitem.setCheckable(True)
        self.prefix_menuitem.setChecked(self.prefix)
        self.prefix_menuitem.triggered.connect(self.on_view_prefix)
        nav_menu = menu.addMenu("Navigate")
        self.back_menuitem = nav_menu.addAction("Back")
        self.back_menuitem.setEnabled(False);
        self.back_menuitem.triggered.connect(self.on_nav_back)
        self.forward_menuitem = nav_menu.addAction("Forward")
        self.forward_menuitem.setEnabled(False);
        self.forward_menuitem.triggered.connect(self.on_nav_forward)
        self.followref_menuitem = nav_menu.addAction("Follow the ref")
        self.followref_menuitem.setEnabled(False);
        self.followref_menuitem.triggered.connect(self.on_followref)        
        help_menu = menu.addMenu("Help")
        help_menu.addAction("About...").triggered.connect(self.on_about)

        # Set up the left pane and the right pane
        tree = self.the_tree = QTreeView()
        tree.header().hide()
        tree.setUniformRowHeights(True)
        tree.clicked.connect(self.on_tree_selection)
        tree.expanded.connect(self.on_tree_expand)
        
        rpane = QWidget()
        rpane_layout = self.rpane_layout = QVBoxLayout()
        rpane.setLayout(rpane_layout)
        die_table = self.die_table = QTableView()
        die_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        die_table.clicked.connect(self.on_attribute_selection)
        die_table.doubleClicked.connect(self.on_attribute_dclick)
        rpane_layout.addWidget(die_table)

        details_table = self.details_table = QTableView()
        details_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        rpane_layout.addWidget(details_table)
        rpane_layout.setStretchFactor(die_table, 0)
        rpane_layout.setStretchFactor(details_table, 1)
        rpane_layout.setContentsMargins(0, 0, 0, 0)

        spl = QSplitter()
        spl.addWidget(self.the_tree)
        spl.addWidget(rpane)
        # All the resizing goes into the right pane by default
        spl.setStretchFactor(0, 0)
        spl.setStretchFactor(1, 1) 
        self.setCentralWidget(spl)
        self.setAcceptDrops(True)

        # The data model placeholders - to be populated once we read a file
        self.die_model = None # Recreated between files
        self.tree_model = None # Reused between DIEs

        self.setWindowTitle("DWARF Explorer")
        self.resize(font_metrics.averageCharWidth() * 250, font_metrics.height() * 60)
    
        self.show()

        # Command line: if can't open, print the error to console
        # On Mac/Linux, the user will see it. On Windows, they won't.
        if len(sys.argv) > 1:
            try:
                if not self.open_file(sys.argv[1]):
                    print("The file contains no DWARF information, or it is in an unsupported format.")
            except Exception as exc:
                print(format(exc))

    # File drag/drop handling - equivalent to open
    def dragEnterEvent(self, evt):
        if evt.mimeData() and evt.mimeData().hasUrls() and len(evt.mimeData().urls()) == 1:
            evt.accept()

    def dropEvent(self, evt):
        self.open_file_interactive(evt.mimeData().urls()[0].toLocalFile())

    # Open a file, display an error if failure
    def open_file_interactive(self, filename):
        try:
            if self.open_file(filename) is None:
                QMessageBox(QMessageBox.Icon.Warning, "DWARF Explorer",
                    "The file contains no DWARF information, or it is in an unsupported format.",
                    QMessageBox.Ok, self).show()
        except Exception as exc:
            QMessageBox(QMessageBox.Icon.Critical, "DWARF Explorer",
                "Error opening the file:\n" + format(exc),
                QMessageBox.Ok, self).show()

    # TODO: list the extensions for the open file dialog?
    def on_open(self):
        dir = os.path.dirname(self.mru[0]) if len(self.mru) > 0 else ''
        filename = QFileDialog.getOpenFileName(self, None, dir)
        if filename[0]:
            self.open_file_interactive(filename[0])

    def populate_mru_menu(self, mru_menu):
        for filename in self.mru:
            mru_menu.addAction(filename).triggered.connect(lambda: self.on_recentfile(filename))

    def on_recentfile(self, filename):
        self.open_file_interactive(filename)

    def on_about(self):
        QMessageBox(QMessageBox.Icon.Information, "About...", "DWARF Explorer v.0.50\ngithub.com/sevaa/dwex",
            QMessageBox.Ok, self).show()

    def display_die(self, index):
        die = index.internalPointer()
        die_table = self.die_table
        if not self.die_model:
            self.die_model = DIETableModel(die, self.prefix)
            die_table.setModel(self.die_model)
        else:
            self.die_model.display_DIE(die)
        self.die_table.resizeColumnsToContents()

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

    def on_tree_expand(self, index):
        self.tree_model.on_expand(index)

    def on_attribute_selection(self, index):
        self.details_table.setModel(self.die_model.get_attribute_details(index.row()))
        self.followref_menuitem.setEnabled(self.die_model.ref_target(index) is not None)

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

    def on_nav_back(self):
        self.on_nav(1)

    def on_nav_forward(self):
        self.on_nav(-1)

    def on_followref(self, index = None):
        if index is None:
            index = self.die_table.getCurrentIndex()
        navitem = self.die_model.ref_target(index)
        if navitem:
            target_tree_index = self.tree_model.index_for_navitem(navitem)
            self.the_tree.setCurrentIndex(target_tree_index)
            # Qt doesn't raise the notification by itself
            self.on_tree_selection(target_tree_index)

    def on_exit(self):
        self.destroy()

    def save_filename_in_mru(self, filename):
        try:
            i = self.mru.index(filename)
        except ValueError:
            i = -1
        if i != 0:
            if i > 0:
                self.mru.pop(i)
            self.mru.insert(0, filename)
            if len(self.mru) > 10:
                self.mru = self.mru[0:10]
            self.save_mru()
            file_menu = self.menuBar().actions()[0].menu()
            if file_menu.actions()[1].menu() is None: # Flimsy... we check if item 2 on the File menu is a submenu or not
                mru_menu = QMenu("Recent files")
                file_menu.insertMenu(file_menu.actions()[1], mru_menu)
            else:
                mru_menu = file_menu.actions()[1].menu()
                mru_menu.clear()
            self.populate_mru_menu(mru_menu)


    # Callback for the Mach-O fat binary opening logic
    # Taking a cue from Hopper or IDA, we parse only one slice at a time
    def resolve_arch(self, arches):
        r = QInputDialog.getItem(self, 'Mach-O Fat Binary', 'Choose an architecture:', arches, 0, False, Qt.WindowType.Dialog)
        return arches.index(r[0]) if r[1] else None

    # Can throw an exception
    # Returns None if it doesn't seem to contain DWARF
    # False if the user cancelled
    def open_file(self, filename):
        self.start_wait()
        try:
            di = read_dwarf(filename, self.resolve_arch)
            if not di: # Covers both False and None
                return di

            # Some cached top level stuff
            di._ranges = None
            di._CUs = [cu for cu in di.iter_CUs()]
            self.tree_model = DWARFTreeModel(di, self.prefix)
            self.the_tree.setModel(self.tree_model)
            self.setWindowTitle("DWARF Explorer - " + os.path.basename(filename))
            self.back_menuitem.setEnabled(False)
            self.forward_menuitem.setEnabled(False)
            self.followref_menuitem.setEnabled(False)
            # Navigation stack - empty
            self.navhistory = []
            self.navpos = -1
            self.save_filename_in_mru(filename)
            return True
        finally:
            self.end_wait()

    def save_mru(self):
        for i, filename in enumerate(self.mru):
            self.sett.setValue("General/MRU%d" % i, filename)

    # Checkmark toggling is handled by the framework
    def on_view_prefix(self, checked):
        self.prefix = checked
        self.sett.setValue('General/Prefix', self.prefix)
        if self.tree_model:
            self.tree_model.set_prefix(checked)

        if self.die_model:
            self.die_model.set_prefix(checked)
        self.die_table.resizeColumnsToContents()

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
        
the_app = QApplication([])
the_window = TheWindow()
the_app.exec_()        

