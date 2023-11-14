import sys, os
sys.path.insert(1, os.getcwd()) # To make sure dwex resolves to local path
import dwex.__main__

def main(debug_crash_reporting, filename, hook_file):
    # Do we need to hook exceptions all the same
    if debug_crash_reporting:
        dwex.__main__.on_exception.prev_exchook = sys.excepthook
        sys.excepthook = dwex.__main__.on_exception

    if len(sys.argv) == 1:
        sys.argv = ['dwex', filename]

    # Monkeypatch to mess with file contents
    old_open_file = dwex.__main__.TheWindow.open_file
    def open_file(self, filename, arch = None):
        r = old_open_file(self, filename, arch)
        hook_file(self.dwarfinfo)
        return r
    
    dwex.__main__.TheWindow.open_file = open_file
    dwex.__main__.main()