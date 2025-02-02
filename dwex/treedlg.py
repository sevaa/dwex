from PyQt6.QtCore import Qt, QAbstractItemModel, QModelIndex
from PyQt6.QtWidgets import *

class TreeModel(QAbstractItemModel):
    """ tree_data is a collection of nodes. A node is either a string or
        a tuple of (string, collection of nodes). Only two levels so far.
        Item's internal object is a tuple of indices
    """
    def __init__(self, tree_data):
        super().__init__()
        self.tree_data = tree_data
        # Since internalPointer doesn't retain the object, need to pregenerate objects that will be used as internal pointers
        # Presuming no more than two levels.
        self.l1indices = tuple((i,) for i in range(len(tree_data)))
        self.l2indices = {(i,): tuple((i, j) for j in range(len(o[1]))) if not isinstance(o, str) else None for (i, o) in enumerate(tree_data)}

    def item_at_index(self, index):
        # Only supports two level nesting. If multilevel trees come up, TODO
        mi = index.internalPointer()
        return self.tree_data[mi[0]] if len(mi) == 1 else self.tree_data[mi[0]][1][mi[1]]

    def index(self, row, col, parent):
        if parent.isValid(): # Second level item
            o = self.l2indices[parent.internalPointer()][row]
        else:
            o = self.l1indices[row]
        return self.createIndex(row, col, o)

    def flags(self, index):
        f = Qt.ItemFlag.ItemIsEnabled
        if index.isValid() and isinstance(self.item_at_index(index), str):
            f |= Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemNeverHasChildren
        return f

    def hasChildren(self, index):
        return not index.isValid() or not isinstance(self.item_at_index(index), str)

    def rowCount(self, parent):
        if parent.isValid():
            o = self.item_at_index(parent)
            return 0 if isinstance(o, str) else len(o[1])
        else:
            return len(self.tree_data)

    def columnCount(self, parent):
        return 1
    
    def parent(self, index):
        if index.isValid():
            mi = index.internalPointer()
            if len(mi) > 1: # Second level item
                return self.createIndex(mi[-2], 0, self.l1indices[mi[-2]])
        return QModelIndex()

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            o = self.item_at_index(index)
            return o if isinstance(o, str) else o[0]

class TreeDlg(QDialog):
    def __init__(self, win, title, data):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.selection = None # A tuple of indices once selected

        self.resize(300, 450)
        ly = QVBoxLayout()

        tree = self.the_tree = QTreeView()
        tree.header().hide()
        tree.setUniformRowHeights(True)
        tree.setModel(TreeModel(data))
        tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        tree.selectionModel().selectionChanged.connect(self.on_sel_change)
        tree.doubleClicked.connect(lambda _: self.accept())
        ly.addWidget(tree)

        buttons = self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel, Qt.Orientation.Horizontal, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        ly.addWidget(buttons)
        self.setWindowTitle(title)
        self.setLayout(ly)

    def on_sel_change(self, sel, prev):
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(len(sel.indexes()) > 0)

    def accept(self):
        sel = self.the_tree.selectedIndexes()
        if len(sel) > 0:
            self.selection = sel[0].internalPointer()
            self.done(QDialog.DialogCode.Accepted)