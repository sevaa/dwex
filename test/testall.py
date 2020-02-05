import os, sys
from PyQt5.QtCore import Qt, QAbstractItemModel, QAbstractTableModel, QModelIndex
sys.path.insert(1, os.path.join(os.getcwd(), "dwex"))
from elftools.dwarf.locationlists import LocationParser, LocationExpr
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
        CU._lineprogram = None
        for die in CU.iter_DIEs():
            if not die.is_null():
                assert die.tag.startswith('DW_TAG_')

                if not m:
                    # With prefix, with low level data, decimal
                    m = DIETableModel(die, True, True, False) 
                else:
                    m.display_DIE(die)

                rc = m.rowCount(dummy_index)
                cc = m.columnCount(dummy_index)
                keys = list(die.attributes.keys())
                # Assuming rows correspond to attributes; 
                # if we introduce non-attribute metadata into the DIE table, this will break
                for r in range(m.meta_count, rc):
                    key = keys[r - m.meta_count]
                    attr = die.attributes[key]
                    form = attr.form
                    value = attr.value
                    # Check the elftools' results first

                    # Check if the key is interpreted properly
                    assert str(key).startswith('DW_AT_')
                    assert str(form).startswith('DW_FORM_')

                    # Check if attributes with locations are all found
                    if form == 'DW_FORM_locexpr':
                        assert LocationParser.attribute_has_location(attr, CU['version'])
                    # The converse is not true; on DWARF2, locations have form DW_FORM_block1

                    # Now check the spell out logic
                    for c in range(0, cc):
                        m.data(m.index(r, c, dummy_index), Qt.DisplayRole)
                    m.get_attribute_details(m.index(r, 0, dummy_index))

def test_file(filename):
    print(filename)
    arches = False
    def save_arches(a):
        nonlocal arches
        arches = a
        return None # Cancel out of loading
    di = read_dwarf(filename, save_arches)
    if arches: # Fat binary - go through all through architectures
        for arch_no in range(0, len(arches)):
            print(arches[arch_no])
            di = read_dwarf(filename, lambda arches:arch_no)
            assert di
            test_dwarfinfo(di)
    else:
        assert di
        test_dwarfinfo(di)

def test_tree(path):
    for f in os.listdir(path):
        full_path = os.path.join(path, f)
        if full_path.endswith('.dSYM') or full_path.endswith('.so'):
            test_file(full_path)
        elif os.path.isdir(full_path):
            test_tree(full_path)

# Caught on GNU_call_site_value

# All sec_offsets must be parsed

# All expressions must be parsed - which forms are expressions?