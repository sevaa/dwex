import subprocess, sys, os
from os import path, environ

def create_shortcut_under(root, exepath, nulfile):
    profile = environ[root]
    s = "$s=(New-Object -COM WScript.Shell).CreateShortcut('" + profile + "\\Microsoft\\Windows\\Start Menu\\Programs\\DWARF Explorer.lnk');"
    s += "$s.TargetPath='" + exepath + "';$s.Save()"
    return subprocess.call(['powershell', s], stdout = nulfile, stderr = nulfile) == 0

def create_shortcut():
    exepath = path.join(path.dirname(sys.executable), "Scripts", "dwex.exe")
    with open(os.devnull, 'w') as nulfile:
        if not create_shortcut_under('ALLUSERSPROFILE', exepath, nulfile):
            create_shortcut_under('APPDATA', exepath, nulfile)

if __name__ == "__main__":
    create_shortcut()
