import subprocess, sys
from os import path, environ

def create_shortcut():
    exepath = path.join(path.dirname(sys.executable), "Scripts", "dwex.exe")
    profile = environ['USERPROFILE']
    s = "$s=(New-Object -COM WScript.Shell).CreateShortcut('" + profile + "\\Start Menu\\Programs\\DWARFExplorer.lnk');"
    s += "$s.TargetPath='"+exepath+"';$s.Description='DWARF Explorer';$s.Save()"
    subprocess.call(['powershell', s])

if __name__ == "__main__":
    create_shortcut()
