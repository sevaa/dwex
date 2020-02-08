DWARF Explorer
==============

A cross-platform GUI utility for visualizing the DWARF
debugging information in executable files, built on top of [pyelftools](https://github.com/eliben/pyelftools) and [filebytes](https://github.com/sashs/filebytes). Runs on Windows, MacOS X, and Linux. Supports parsing the following file types for DWARF data:
 - ELF (Linux, Android)
 - Mach-O (MacOS X, iOS)
 - PE (Windows, Cygwin)

This project came from my desire to see and navigate the DWARF tree of compiled Android and iOS binaries. Seeing the DIEs is easy enough with utilities like `readelf` or `dwarfdump`. However, chasing inter-DIE references back and forth is not straightforward with those.

The utility might be of use for anyone who is building DWARF parsers for one or another reason, especially if their preferred parsing library is `pyelftools`.

Note that regular Windows executables (EXE/DLL files) are PE files but don't, as a rule, contain DWARF information. The Microsoft toolchains (Visual Studio and the like) produce debugging information in Microsoft's own format, Program Database (PDB). There are, though, a couple of toolchains that produce PE files with DWARF debug info in them - notably GCC under Cygwin. DWARF Explorer is compatible with those.

DWARF Explorer supports DWARF version 2-4, like the pyelftools library it's based on. DWARF v5 exists, and will be eventually supported, but it's not mainstream yet.

Requirements and Dependencies
------------
 - Python 3.5+
 - PyQt5
 - filebytes 0.10.1+

Installlation
-------------

Run `pip install dwex` from the command line, under `sudo` or elevated command line if necessary.

On Windows, if `pip` and/or Python is not in PATH, use `c:\Python38\python -m pip install dwex`, substituting your own path to Python 3.

Alternatively, get the Python source tree from Github, and run `python setup.py install` in the root folder of the package. In this scenario, you'd have to install PyQt5 and `filebytes` separately - with `pip install pyqt5`.

On Linux, sometimes the `python` command defaults to Python 2 while Python 3 is installed side by side. In this case, use `python3` and `pip3`, respectively. Use `python -V` to check.

Once you install it, there will be a `dwex` command. On Windows, there will be a `dwex.exe` in
the `Scripts` folder under the Python folder, and also a start menu item "DWARF Explorer".

Usage
-----

Click Open in the File menu, choose your executable, and eyeball the DWARF tree. Alternatively, drag and drop an executable onto the main window. You can open by dropping a dSYM bundle folder, too.

Click on DIEs in the tree to see their contents. DIE attributes that have a substructure or point at larger data structures are clickable.

DIE attributes that contain references to other DIEs are rendered in blue; the link can be followed by double-click. To come back to the original DIE, use Navigate/Back or an appropriate keyboard shortcut (those vary between platforms).


