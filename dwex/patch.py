import elftools.dwarf.enums

def monkeypatch():
    #https://docs.hdoc.io/hdoc/llvm-project/e051F173385B23DEF.html
    elftools.dwarf.enums.ENUM_DW_AT["DW_AT_APPLE_sdk"] = 0x3fef