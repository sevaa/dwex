from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
from PyQt5.QtGui import QFontMetrics 
from PyQt5.QtWidgets import *
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo, DebugSectionDescriptor, DwarfConfig
from types import MethodType
import sys, os, io, struct
from os import path
from die import DIETableModel

# Supports both / and \ - current system separator might not match the system the file came from
# so os.path.basename won't do
def strip_path(filename):
    p = filename.rfind("/")
    pbsl = filename.rfind("\\")
    if pbsl >= 0 and (p < 0 or pbsl > p):
        p = pbsl
    return filename[p+1:] if p >= 0 else filename

#------------------------------------------------
# CU tree formatter
#------------------------------------------------    

# Some additional data for every DIE
def with_index(o, i):
    o._i = i
    o._child_count = None
    return o

class DWARFTreeModel(QAbstractItemModel):
    def __init__(self, di):
        QAbstractItemModel.__init__(self)
        self.prefix = False # TODO: make it a persistent setting
        self.TopDIEs = [with_index(CU.get_top_DIE(), i) for (i, CU) in enumerate(di.iter_CUs())]

    def index(self, row, col, parent):
        if parent.isValid():
            parent_die = parent.internalPointer()
            if parent_die._child_count is None: # Never expanded, but the tree view needs a placeholder
                return self.createIndex(row, col)
            else:
                children = [die for die in parent_die.iter_children()] # Cached, fast
                return self.createIndex(row, col, children[row])
        else:
            return self.createIndex(row, col, self.TopDIEs[row])
        return QModelIndex()

    def rowCount(self, parent):
        if parent.isValid():
            parent_die = parent.internalPointer()
            if parent_die is None: # The item is a temporary placeholder
                return 0

            if not parent_die.has_children: # Legitimately nothing
                return 0
            elif parent_die._child_count is None: # Never expanded, return 1 to enable the expansion on the UI
                return 1
            else: # DIEs already read and cached
                return parent_die._child_count
        else:
            return len(self.TopDIEs)

    def columnCount(self, parent):
        return 1

    def parent(self, index):
        die = index.internalPointer()
        parent = die.get_parent()
        if not parent:
            return QModelIndex()
        else:
            return self.createIndex(parent._i, 0, parent)

    def data(self, index, role):
        die = index.internalPointer() # Should never come for a placeholder entry
        if role == Qt.DisplayRole:
            if die is None:
                return "Please wait..."

            if die.tag == 'DW_TAG_compile_unit' or die.tag == 'DW_TAG_partial_unit':
                source_name = die.attributes['DW_AT_name'].value.decode('utf-8')
                return strip_path(source_name)
            else:
                s = die.tag[0 if self.prefix else 7:]
                if 'DW_AT_name' in die.attributes:
                    s += ": " + die.attributes['DW_AT_name'].value.decode('utf-8')
                return s
        elif role == Qt.ToolTipRole:
            if die.tag == 'DW_TAG_compile_unit' or die.tag == 'DW_TAG_partial_unit':
                return die.attributes['DW_AT_name'].value.decode('utf-8')

    def set_prefix(self, prefix):
        if prefix != self.prefix:
            self.prefix = prefix
            self.dataChanged.emit(
                self.createIndex(0, 0, self.TopDIEs[0]),
                self.createIndex(len(self.TopDIEs)-1, 0, self.TopDIEs[-1]))

    def on_expand(self, parent):
        parent_die = parent.internalPointer()
        if parent_die._child_count is None:
            the_window.start_wait()
            children = [with_index(die, i) for (i, die) in enumerate(parent_die.iter_children())] # Slow, parses the file
            child_count = len(children)
            parent_die._child_count = child_count
            self.rowsRemoved.emit(parent, 0, 0)
            self.rowsInserted.emit(parent, 0, len(children) - 1)
            the_window.end_wait()

#-----------------------------------------------------------------
#  The one and only main window class
#-----------------------------------------------------------------

class TheWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.wait_level = 0

        menu = self.menuBar()
        file_menu = menu.addMenu("&File")
        file_menu.addAction("Open...").triggered.connect(self.on_open)
        file_menu.addAction("E&xit").triggered.connect(self.on_exit)
        view_menu = menu.addMenu("View")
        self.prefix_menuitem = view_menu.addAction("DWARF prefix")
        self.prefix_menuitem.setCheckable(True)
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

        font_metrics = self.font_metrics = QFontMetrics(QApplication.font())

        # Set up the left pane and the right pane
        tree = self.the_tree = QTreeView()
        tree.header().hide()
        tree.setUniformRowHeights(True)
        tree.clicked.connect(self.on_tree_selection)
        tree.expanded.connect(self.on_tree_expand)
        
        rpane = QWidget()
        rpane_layout = self.rpane_layout = QVBoxLayout()
        rpane_layout.setContentsMargins(0, 0, 0, 0)
        rpane.setLayout(rpane_layout)
        die_table = self.die_table = QTableView()
        die_table.setColumnWidth(0, font_metrics.averageCharWidth()*20)
        die_table.setColumnWidth(0, font_metrics.averageCharWidth()*10)
        die_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        die_table.clicked.connect(self.on_attribute_selection)
        die_table.doubleClicked.connect(self.on_attribute_dclick)
        rpane_layout.addWidget(die_table)

        details_table = self.details_table = QTableView()
        details_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        rpane_layout.addWidget(details_table)
        rpane_layout.setStretchFactor(die_table, 0)
        rpane_layout.setStretchFactor(details_table, 1)

        spl = QSplitter()
        spl.addWidget(self.the_tree)
        spl.addWidget(rpane)
        # All the resizing goes into the right pane by default
        spl.setStretchFactor(0, 0)
        spl.setStretchFactor(1, 1) 
        self.setCentralWidget(spl)
        self.setAcceptDrops(True)

        self.die_model = None # Recreated between files
        self.tree_model = None # Reused between DIEs

        self.setWindowTitle("DWARF Explorer")
        self.resize(font_metrics.averageCharWidth() * 250, font_metrics.height() * 60)
    
        self.show() # TODO: check the action on command line with nonexistent file

        if len(sys.argv) > 1:
            try:
                if not self.open_file(sys.argv[1]):
                    print("The file contains no DWARF information, or it is in an unsupported format.")
            except Exception as exc:
                print(format(exc)) # Windows users won't see it.

    # File drag/drop handling - equivalent to open
    # TODO: list the extensions...
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

    def on_open(self):
        filename = QFileDialog.getOpenFileName(self)
        if filename[0]:
            self.open_file_interactive(filename[0])

    def on_about(self):
        QMessageBox(QMessageBox.Icon.Information, "About...", "DWARF Explorer v.0.50",
            QMessageBox.Ok, self).show()

    def on_tree_selection(self, index):
        die = index.internalPointer()
        die_table = self.die_table
        if not self.die_model:
            self.die_model = DIETableModel(die)
            self.die_model.set_prefix(self.prefix_menuitem.isChecked())
            die_table.setModel(self.die_model)
        else:
            self.die_model.display_DIE(die)

        #attr_count = self.die_model.rowCount(None)
        #TODO: resize the attribute table dynamically
        #die_table.resize(die_table.size().width(),
        #    die_table.rowViewportPosition(attr_count-1) + 
        #        die_table.rowHeight(attr_count-1) +
        #        die_table.horizontalHeader().size().height() + 1 + attr_count)
        #self.rpane_layout.update()

    def on_tree_expand(self, index):
        self.tree_model.on_expand(index)

    def on_attribute_selection(self, index):
        self.details_table.setModel(self.die_model.get_attribute_details(index.row()))

    def on_attribute_dclick(self, index):
        pass

    def on_nav_back(self):
        pass

    def on_nav_forward(self):
        pass

    def on_followref(self):
        pass

    def on_exit(self):
        self.destroy()

    #---------------------------------------------------

    def read_pe(self, filename):
        from filebytes.pe import PE, IMAGE_FILE_MACHINE

        pefile = PE(filename)
        # Filebytes doesn't resolve section names via the strtable so far
        file_header = pefile.imageNtHeaders.header.FileHeader
        IMAGE_SIZEOF_SYMBOL = 18 # TODO: check one 64 bits
        strtable_offset = file_header.PointerToSymbolTable + IMAGE_SIZEOF_SYMBOL * file_header.NumberOfSymbols
        def resolve_name(section_name):
            if section_name.startswith('/'):
                name_offset = int(section_name[1:]) + strtable_offset
                s = bytearray()
                while pefile._bytes[name_offset] != 0:
                    s.append(pefile._bytes[name_offset])
                    name_offset += 1
                return bytes(s).decode('ASCII')
            else:
                return section_name

        # Section's raw size might be padded
        sections = [(resolve_name(section.name), section,
            section.header.PhysicalAddress_or_VirtualSize,
            section.header.SizeOfRawData)
            for section in pefile.sections]
        data = {name: DebugSectionDescriptor(
                io.BytesIO(section.bytes),
                name,
                None,
                raw_size if virtual_size == 0 else min((raw_size, virtual_size)),
                0)
            for (name, section, virtual_size, raw_size) in sections}

        machine = pefile.imageNtHeaders.header.FileHeader.Machine
        is64 = machine in (IMAGE_FILE_MACHINE.AMD64, 0xaa64, IMAGE_FILE_MACHINE.IA64) # There are also some exotic architectures...
        arches = {
            IMAGE_FILE_MACHINE.ARM: "arm",
            IMAGE_FILE_MACHINE.ARMV: "armv5",	
            0xaa64: "arm64", # IMAGE_FILE_MACHINE_ARM64	
            IMAGE_FILE_MACHINE.I386: "i386",
            IMAGE_FILE_MACHINE.AMD64: "amd64",
            IMAGE_FILE_MACHINE.THUMB: "arm"}

        return DWARFInfo(
            config=DwarfConfig(
                little_endian = True,
                default_address_size = 8 if is64 else 4,
                machine_arch = arches[machine]
            ),
            debug_info_sec = data['.debug_info'],
            debug_aranges_sec = data['.debug_aranges'] if '.debug_aranges' in data else None,
            debug_abbrev_sec = data['.debug_abbrev'] if '.debug_abbrev' in data else None,
            debug_frame_sec = data['.debug_frame'] if '.debug_frame' in data else None,
            eh_frame_sec = None, # TODO: check with Cygwin's G++
            debug_str_sec = data['.debug_str'] if '.debug_str' in data else None,
            debug_loc_sec = data['.debug_loc'] if '.debug_loc' in data else None,
            debug_ranges_sec = data['.debug_ranges'] if '.debug_ranges' in data else None,
            debug_line_sec = data['.debug_line'] if '.debug_line' in data else None,
            debug_pubtypes_sec = data['.debug_pubtypes'] if '.debug_pubtypes' in data else None,
            debug_pubnames_sec = data['.debug_pubnames'] if '.debug_pubnames' in data else None,
        )

    def read_macho(self, filename):
        from filebytes.mach_o import MachO, CpuType, TypeFlags
        macho = MachO(filename)
        # TODO: find a MachO file that is not a fat binary
        if macho.isFat:
            arches = {CpuType.I386: "x86",
                CpuType.X86_64: "amd64",
                CpuType.MIPS: "mips",
                CpuType.ARM: "arm",
                CpuType.ARM64: "arm64",
                CpuType.POWERPC: "ppc",
                CpuType.POWERPC64: "ppc64"}

            # One CPU type where it's relevant - armv6, armv7, armv7s coexisted in the toolchain for a while
            arm_types = {
                5:"v4t", 6:"v6", 7:"v5", 7:"v5tej",
                8:"xscale", 9:"v7", 11:"v7s", 12:"v7k",   
                14:"v6m", 15:"v7m", 16:"v7em"}

            slices = [arches[slice.machHeader.header.cputype] +
                arm_types[slice.machHeader.header.cpusubtype] if slice.machHeader.header.cputype == CpuType.ARM else ''
                for slice in macho.fatArches]
            r = QInputDialog.getItem(self, 'Mach-O Fat Binary', 'Choose an architecture:', slices, 0, False, Qt.WindowType.Dialog)
            if r[1]:
                macho = macho.fatArches[slices.index(r[0])]
            else:
                return False # User cancellation result

        # We proceed with macho being a arch-specific file, or a slice within a fat binary
        data = {
            section.name: DebugSectionDescriptor(io.BytesIO(section.bytes), section.name, None, len(section.bytes), 0)
            for loadcmd in macho.loadCommands
            if getattr(loadcmd, 'name', None) == '__DWARF'
            for section in loadcmd.sections
        }

        # TODO: distinguish between arm flavors?
        arch = macho.machHeader.header.cputype
        return DWARFInfo(
            config=DwarfConfig(
                little_endian=True,
                default_address_size = 8 if (arch | TypeFlags.ABI64) != 0 else 4,
                machine_arch= arches[arch]
            ),
            debug_info_sec=data['__debug_info'],
            debug_aranges_sec=data['__debug_aranges'],
            debug_abbrev_sec=data['__debug_abbrev'],
            debug_frame_sec=data['__debug_frame'] if '__debug_frame' in data else None,
            eh_frame_sec=None,
            debug_str_sec=data['__debug_str'],
            debug_loc_sec=data['__debug_loc'],
            debug_ranges_sec=data['__debug_ranges'],
            debug_line_sec=data['__debug_line'],
            debug_pubtypes_sec=data['__debug_pubtypes'],
            debug_pubnames_sec=data['__debug_pubtypes'],
        )

    # Already in wait cursor mode
    # Returns DWARFInfo
    # Or None if not a DWARF containing file
    # Or False if user has cancelled
    def read_dwarf(self, filename):
        file = None
        try:
            if path.isfile(filename): # On MacOS, opening dSYM bundles as is would be right
                file = open(filename, 'rb')
                signature = file.read(4)
                if signature[0:2] == b'MZ': # DOS header - this might be a PE. Don't verify the PE header, just feed it to the parser
                    file.close()
                    file = None
                    return self.read_pe(filename)
                elif signature == b'\x7FELF': #It's an ELF
                    file.seek(0)
                    elffile = ELFFile(file)
                    file = None # Keep the file open
                    return elffile.get_dwarf_info()
                elif struct.unpack('>I', signature)[0] in (0xcafebabe, 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe): # Mach-O fat binary, 32- and 64-bit Mach-O in big- or little-endian format
                    return self.read_macho(filename)
            elif path.isdir(filename):
                # Is it a dSYM bundle?
                nameparts = path.basename(filename).split('.') # Typical bundle name: appname.app.dSYM
                dsym_file = path.join(filename, 'Contents', 'Resources', 'DWARF', nameparts[0])
                if path.exists(dsym_file):
                    return self.read_macho(dsym_file)
                # Any other bundle formats we should be aware of?
            return None
        finally:
            if file:
                file.close()

    # Can throw an exception
    # Returns false if it doesn't seem to contain DWARF
    def open_file(self, filename):
        # TODO: mach-o, PE
        self.start_wait()
        try:
            di = self.read_dwarf(filename)
            if not di: # Covers both False and None
                return di

            # Placeholders for cached stuff
            di._ranges = None
            self.tree_model = DWARFTreeModel(di)
            self.tree_model.set_prefix(self.prefix_menuitem.isChecked())
            self.the_tree.setModel(self.tree_model)
            self.setWindowTitle("DWARF Explorer - " + path.basename(filename))
            self.back_menuitem.setEnabled(False)
            self.forward_menuitem.setEnabled(False)
            self.followref_menuitem.setEnabled(False)
            self.navhistory = []
            return True
        finally:
            self.end_wait()

    # Checkmark toggling is handled by the framework
    def on_view_prefix(self, checked):
        self.tree_model.set_prefix(checked)
        if self.die_model:
            self.die_model.set_prefix(checked)

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

