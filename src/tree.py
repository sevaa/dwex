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
    o._children = None
    return o

def load_children(parent_die):
    # Load and cache child DIEs in the parent DIE, if necessary
    # Assumes the check if the DIE has children has been already performed
    if parent_die._children is None:
        # TODO: wait cursor here. It may cause disk I/O
        parent_die._children = [with_index(die, i) for (i, die) in enumerate(parent_die.iter_children())]    


class DWARFTreeModel(QAbstractItemModel):
    def __init__(self, di, prefix):
        QAbstractItemModel.__init__(self)
        self.prefix = prefix
        self.TopDIEs = [with_index(CU.get_top_DIE(), i) for (i, CU) in enumerate(di._CUs)]

    # Qt callbacks. QTreeView supports progressive loading, as long as you feed it the "item has children" bit in advance

    def index(self, row, col, parent):
        if parent.isValid():
            parent_die = parent.internalPointer()
            # print("child of %s" % parent_die.tag)
            load_children(parent_die)
            return self.createIndex(row, col, parent_die._children[row])
        else:
            return self.createIndex(row, col, self.TopDIEs[row])
        return QModelIndex()

    def flags(self, index):
        f = Qt.ItemIsSelectable | Qt.ItemIsEnabled
        if index.isValid() and not index.internalPointer().has_children:
            f = f | Qt.ItemNeverHasChildren
        return f

    def hasChildren(self, index):
        return not index.isValid() or index.internalPointer().has_children

    def rowCount(self, parent):
        if parent.isValid():
            parent_die = parent.internalPointer()
            # print('rcount of %s' % parent_die.tag)
            if not parent_die.has_children: # Legitimately nothing
                return 0
            else:
                load_children(parent_die)
                return len(parent_die._children)
        else:
            return len(self.TopDIEs)

    def columnCount(self, parent):
        return 1

    def parent(self, index):
        if index.isValid():
            parent = index.internalPointer().get_parent()
            if parent:
                return self.createIndex(parent._i, 0, parent)
        return QModelIndex()

    def data(self, index, role):
        die = index.internalPointer() # Should never come for a placeholder entry
        if role == Qt.DisplayRole:
            if die.tag == 'DW_TAG_compile_unit' or die.tag == 'DW_TAG_partial_unit': # CU/top die: return file name
                source_name = die.attributes['DW_AT_name'].value.decode('utf-8')
                return strip_path(source_name)
            else: # Return tag, with name if possible
                s = die.tag if self.prefix or not die.tag.startswith('DW_TAG_') else die.tag[7:]
                if 'DW_AT_name' in die.attributes:
                    s += ": " + die.attributes['DW_AT_name'].value.decode('utf-8')
                return s
        elif role == Qt.ToolTipRole:
            if die.tag == 'DW_TAG_compile_unit' or die.tag == 'DW_TAG_partial_unit':
                return die.attributes['DW_AT_name'].value.decode('utf-8')

    # The rest is not Qt callbacks

    def set_prefix(self, prefix):
        if prefix != self.prefix:
            self.prefix = prefix
            self.dataChanged.emit(
                self.createIndex(0, 0, self.TopDIEs[0]),
                self.createIndex(len(self.TopDIEs)-1, 0, self.TopDIEs[-1]))    

    # Identifier for the current tree node that you can navigate to
    # For the back-forward logic
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
        if '_i' in dir(target_die): # DIE already iterated over
            return self.createIndex(target_die._i, 0, target_die)
        else: # Found the DIE, but the tree was never opened this deep. Read the tree along the path to the target DIE
            index = False
            while '_i' not in dir(target_die):
                parent_die = target_die.get_parent()
                load_children(parent_die)
                if not index: # After the first iteration, the one in the direct parent of target_die, target_die will have _i
                    index = self.createIndex(target_die._i, 0, target_die)
                target_die = parent_die
            return index


