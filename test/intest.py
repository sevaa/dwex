import sys, os
sys.path.insert(1, os.getcwd()) # To make sure dwex resolves to local path
import dwex.__main__

# Hook exceptions all the same
dwex.__main__.on_exception.prev_exchook = sys.excepthook
sys.excepthook = dwex.__main__.on_exception

# TODO: stable test file
if len(sys.argv) == 1:
    sys.argv = ['dwex', 'samples\\An-2.60.3-j-ARMv7-libyarxi.so']

# Monkeypatch to mess with file contents
old_open_file = dwex.__main__.TheWindow.open_file
def open_file(self, filename, arch = None):
    r = old_open_file(self, filename, arch)
    buf = self.dwarfinfo.debug_info_sec.stream.getbuffer()
    #buf[0x9e900] = 0xff # Bogus abbrev code
    #9e81e - subprogram die
    #buf[0x9e8ed+3] = 0xff # Bogus offset in AT_type, so that it leads nowhere
    # Frame_base, bogus opcode in attr block
    buf[0x9e8f9] = 0x7f
    return r
dwex.__main__.TheWindow.open_file = open_file

dwex.__main__.main()