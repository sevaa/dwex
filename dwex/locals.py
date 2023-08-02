from PyQt6.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
from PyQt6.QtWidgets import *
from elftools.dwarf.locationlists import LocationParser, LocationExpr
from .die import ip_in_range

#0x25af0

headers = ["Name", "Expression"]

def has_ip(die):
    attr = die.attributes
    return 'DW_AT_ranges' in attr or ('DW_AT_low_pc' in attr and 'DW_AT_high_pc' in attr)  

class LocalsModel(QAbstractTableModel):
    def __init__(self):
        QAbstractTableModel.__init__(self)

    def headerData(self, section, ori, role):
        if ori == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return headers[section]

    def rowCount(self, parent):
        return 2

    def columnCount(self, parent):
        return 2

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            return "Boo" # self.values[index.row()][index.column()]"

class LocalsDlg(QDialog):
    def __init__(self, win, di):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.dwarfinfo = di
        if di._locparser is None:
            di._locparser = LocationParser(di.location_lists())
        if not di._ranges:
            di._ranges = di.range_lists()            
        if not di._aranges:
            di._aranges = di.get_aranges()

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
        self.model = LocalsModel()
        self.locals.setModel(self.model)
        ly.addWidget(self.locals)        

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, Qt.Orientation.Horizontal, self)
        buttons.accepted.connect(self.reject)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)
        self.setWindowTitle('Locals at address')
        self.setLayout(ly)

    def on_check(self, bu):
        try:
            address = int(self.address.text(), 0)
            load_address = int(self.start_address.text(), 0)
        except ValueError:
            return

        start_address = self.dwarfinfo._start_address
        address += start_address - load_address # Now relative to the preferred start address
        Funcs = []

        # Find the CU for the current
        di = self.dwarfinfo
        if di._aranges:
            cuoffset = di._aranges.cu_offset_at_addr(address)
            if cuoffset is None:
                #print("IP not in DWARF data")
                return
            cu = di._parse_CU_at_offset(cuoffset)
        else:
            for cu in di._unsorted_CUs:
                if ip_in_range(cu.get_top_DIE(), address):
                    break

        # Find the function(s) at the address
        top_die = cu.get_top_DIE()
        first_die = next(top_die.iter_children())
        if first_die is None:
            return
        has_siblings = "DW_AT_sibling" in first_die.attributes 
        if has_siblings:
            die_list = (die for die in cu.iter_DIE_children(top_die))
        else:
            die_list = (die for die in cu.iter_DIEs())

        for die in die_list:
            if die.tag == 'DW_TAG_subprogram' and has_ip(die):
                if 'DW_AT_range' in die.attributes:
                    cu_base = top_die.attributes['DW_AT_low_pc'].value - start_address
                    rl = di._ranges.get_range_list_at_offset(die.attributes['DW_AT_ranges'].value)
                    Locs = []
                    for r in rl:
                        Locs.append("%x-%x", (cu_base+r.begin_offset, cu_base+r.end_offset))
                        if r.begin_offset <= address - cu_base < r.end_offset:
                            Funcs.append(die)
                    Locs = ",".join(Locs)
                else:
                    l = die.attributes['DW_AT_low_pc'].value - start_address
                    h = die.attributes['DW_AT_high_pc'].value
                    if not die.attributes['DW_AT_high_pc'].form == 'DW_FORM_addr':
                        h += l
                    else:
                        h -= start_address
                    Locs = "%x-%x" % (l, h)
                    if address >= l and address < h:
                        Funcs.append(die)
                #f.write("%x:%s\n" % (die.offset, Locs))            

