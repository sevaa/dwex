from bisect import bisect_left
from PyQt5.QtCore import Qt, QAbstractItemModel, QModelIndex

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
    def __init__(self, di, prefix):
        QAbstractItemModel.__init__(self)
        self.prefix = prefix
        self.TopDIEs = [with_index(CU.get_top_DIE(), i) for (i, CU) in enumerate(di._CUs)]

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

    # That's where the progressive loading lives.
    def on_expand(self, parent):
        parent_die = parent.internalPointer()
        if parent_die._child_count is None:
            children = [with_index(die, i) for (i, die) in enumerate(parent_die.iter_children())] # Slow, parses the file
            child_count = len(children)
            parent_die._child_count = child_count
            self.rowsRemoved.emit(parent, 0, 0)
            self.rowsInserted.emit(parent, 0, len(children) - 1)

    # Identifier for the current tree node that you can navigate to
    # Specifically, (cu, offset within the info section)
    def get_navitem(self, index):
        die = index.internalPointer()
        return (die.cu, die.offset)

    # navitem is (CU, offset within the info section)
    # returns an index within the tree
    def index_for_navitem(self, navitem):
        target_cu, target_offset = navitem
        # Random access is a tricky proposition in the current version. Parse the whole CU.
        for die in target_cu.iter_DIEs():
            pass

        i = bisect_left(target_cu._diemap, target_offset)
        target_die = target_cu._dielist[i]
        if '_i' in dir(target_die): # DIE already once iterated over
            return self.createIndex(target_die._i, 0, target_die)
        else: # Found the DIE, but the tree was never opened this deep. Restore the indices.
            while '_i' not in dir(target_die):
                parent_die = target_die.get_parent()
                for i, die in enumerate(parent_die.iter_children()):
                    with_index(die, i)
                    if die.offset == target_offset:
                        index = self.createIndex(i, 0, target_die)
                target_die = parent_die
            return index


