from elftools.elf.elffile import ELFFile

with open('..\\samples_todo\\find', 'rb') as file:
    efile = ELFFile(file)
    di = efile.get_dwarf_info() 
    for cu in di.iter_CUs():
        for die in cu.get_top_DIE().iter_children():
            print(die.tag)

    
