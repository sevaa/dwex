DWARF Explorer
==============

A cross platform GUI utility for visualizing the DWARF
debugging information in executable files, built on top of of [pyelftools](https://github.com/eliben/pyelftools) and [filebytes](https://github.com/sashs/filebytes). Runs on Windows, MacOS X, and Linux. Supports parsing the following file types for DWARF data:
 - ELF (Linux, Android)
 - Mach-O (MacOS X, iOS)
 - PE (Windows, Cygwin)

This project came from my desire to see and navigate the DWARF tree of compiled binaries. Seeing the DIEs is easy enough with utilities like `readelf` or `dwarfdump`. However, chasing inter-DIE references back and forth is not straightforward with those.

The utility might be of use for anyone who is building DWARF parsers for one or another reason, especially if their preferred parsing library is `pyelftools`.

Requirements
------------
 - Python 3.5+
 - PyQt5

Installlation
-------------

Run `pip install dwex`, under `sudo` if necessary.

Alternatively, get the Python sources from Github, and run `python setup.py install` using your favorite Python 3 interpreter in the root folder of the package. In this scenario, you'd have
to install PyQt5 separately - with `pip install pyqt5`.

On Windows, if `pip` and/or Python is not in PATH, use `c:\Python35\python -m pip install pyqt5`, substituting your own path to Python.

Once you install it, there will be a `dwex` command. On Windows, there will be a `dwex.exe` in
`Scripts` under the Python folder, and also a start menu item "DWARF Explorer".

Usage
-----

Click Open in the File menu, choose your executable, and eyeball the DWARF tree. Alternatively, drag and drop an executable onto the main window. You can open by dropping a dSYM bundle folder, too.

Click on DIEs in the tree to see their contents. DIE attributes that have a substructure or point at larger data structures are clickable.

DIE attributes that contain references to other DIEs are rendered in blue; the link can be followed by double-click. To come back to the original DIE, use Navigate/Back or an appropriate keyboatrd shortcut (those vary between platforms).


