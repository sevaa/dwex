DWARF Explorer
==============

A cross platform GUI utility for visualizing the DWARF
debugging information in executable files, built on top of of [pyelftools](https://github.com/eliben/pyelftools) and [filebytes](https://github.com/sashs/filebytes). Runs on Windows, MacOS X, and Linux. Supports parsing the following file types for DWARF data:
 - ELF (Linux, Android)
 - Mach0-O (MacOS X, iOS)
 - PE (Windows, Cygwin)

Requirements
------------
 - Python 3.5+
 - PyQt5

Installlation
-------------

For now, there isn't any. Get the Python sources, and run dwex/__main__.py using your favorite Python 3 interpreter. I'll publish it on PyPi soon.

Usage
-----

Click Open in the File menu, choose your executable, and eyeball the DWARF tree.


