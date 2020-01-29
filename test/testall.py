import os, sys
from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
sys.path.insert(1, os.path.join(os.getcwd(), "src"))
from formats import read_dwarf
from die import DIETableModel
from tree import strip_path

def test_dwarfinfo(di):
    # Some global cache setup in line with the app proper
    di._ranges = None
    di._CUs = [cu for cu in di.iter_CUs()]
    di._locparser = None

    m = False
    dummy_index = QModelIndex()
    for CU in di._CUs:
        print("%s" % strip_path(CU.get_top_DIE().attributes['DW_AT_name'].value.decode('ASCII')))
        for die in CU.iter_DIEs():
            if not m:
                m = DIETableModel(die, True, True, False)
            else:
                m.display_DIE(die)

            rc = m.rowCount(dummy_index)
            cc = m.columnCount(dummy_index)
            for r in range(0, rc):
                for c in range(0, cc):
                    m.data(m.index(r, c, dummy_index), Qt.DisplayRole)
                m.get_attribute_details(r)

def test_file(filename):
    print(filename)
    arches = False
    def f(a):
        nonlocal arches
        arches = a
        return None
    di = read_dwarf(filename, f)
    if arches:
        for arch_no in range(0, len(arches)):
            def g(arches):
                return arch_no
            di = read_dwarf(filename, g)
            assert di
            test_dwarfinfo(di)
    else:
        assert di
        test_dwarfinfo(di)

#test_file("H:\\dev\\dwex\\samples\\a.exe")
test_file("H:\\dev\\dwex\\samples\\YarxiMin.app.dSYM")


# test that attributes where LocationParser.attribute_has_location returns false
# don't have DW_FORM_locexpr
# Caught on GNU_call_site_value

# All sec_offsets must be parsed

# All expressions must be parsed - which forms are expressions?