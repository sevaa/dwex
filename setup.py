from setuptools import setup
from setuptools.command.install import install
import platform, sys, os, site
from os import path, environ, makedirs

#------------------------------------
# Start menu item creation on Windows
#------------------------------------

def create_shortcut_under(root, exepath):
    profile = environ[root]
    linkpath = path.join(profile, "Microsoft", "Windows", "Start Menu", "Programs", "DWARF Explorer.lnk")
    try:
        from win32com.client import Dispatch
        from pywintypes import com_error
        try:
            sh = Dispatch('WScript.Shell')
            link = sh.CreateShortcut(linkpath)
            link.TargetPath = exepath
            link.Save()
            return True
        except com_error:
            return False
    except ImportError:
        import subprocess
        s = "$s=(New-Object -COM WScript.Shell).CreateShortcut('" + linkpath + "');$s.TargetPath='" + exepath + "';$s.Save()"
        return subprocess.call(['powershell', s], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL) == 0

def create_shortcut(inst):
    try:
        exepath = path.join(path.dirname(sys.executable), "Scripts", "dwex.exe")
        if not path.exists(exepath):
            exepath = path.join(path.dirname(site.getusersitepackages()), "Scripts", "dwex.exe")

        if not create_shortcut_under('ALLUSERSPROFILE', exepath):
            create_shortcut_under('APPDATA', exepath)
    except:
        pass

#--------------------------------------    

def register_desktop_app():
    try:
        import base64, subprocess
        with open('/usr/share/applications/dwex.desktop', 'w') as f:
            f.write("[Desktop Entry]\nVersion=1.1\nType=Application\nName=DWARF Explorer\nComment=Debug information visualizer\nExec=dwex\nTerminal=false\nIcon=dwex\nCategories=Development;Debugger;\n")
        with open('/usr/share/icons/hicolor/48x48/apps/dwex.png', 'wb') as f:
            f.write(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAAKnRFWHRDcmVhdGlvbiBUaW1lANHhIDYg7e7/IDIwMjEgMTM6MDg6NDcgLTA1MDBuo0qzAAAAB3RJTUUH5QsGEQ8VL0d/PwAAAAlwSFlzAAALEgAACxIB0t1+/AAAAARnQU1BAACxjwv8YQUAAAAGUExURf///wAAAFXC034AAACkSURBVHjavdNREoUgCAXQyw5g/5sNxEoEpvc+yim0OcUoJvBRE2sAaeQRAkgB0NdBbJcPfgMNbglI8w9AAu1tDjXQv8DEUgH1gAwaDKQEu3kDWzBVIBNCReaG+Fc7oIAvGt1/g61cnsGnaM9nn0B89Rloq9UF4JDJd9VHsSILSIR7jiHTAm0qbiHNau7StlEXlCU5T0ALS65Zdh5lp+VwtvByOwCIiA5ALXz03AAAAABJRU5ErkJggg=="))
        subprocess.call('update-desktop-database')
    except:
        pass

#--------------------------------------
# App bundle on MacOS X
#--------------------------------------
def save_as_plist(d, f):
    f.write('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>')
    for (key, value) in d.items():
        f.write(f'<key>{key}</key>')
        if isinstance(value, str):
            f.write(f'<string>{value}</string>')
        elif isinstance(value, (tuple, list)):
            values = ''.join(f'<string>{e}</string>' for e in value)
            f.write(f'<array>{values}</array>')
    f.write('</dict></plist>')

def create_app_bundle_under(app_ver, apps):
    p = path.join(apps, 'DWARF Explorer.app')
    makedirs(p, exist_ok=True)
    p = path.join(p, 'Contents')
    makedirs(p, exist_ok=True)
    with open(path.join(p, 'Info.plist'), 'wt') as f:
        save_as_plist({
            'CFBundleDevelopmentRegion': 'English',
            'CFBundleDisplayName': 'DWARF Explorer',
            'CFBundleExecutable': 'dwex',
            'CFBundleIdentifier': 'com.dwex.dwex',
            'CFBundleInfoDictionaryVersion': '6.0',
            'CFBundleName': 'DWARF Explorer',
            'CFBundlePackageType': 'APPL',
            'CFBundleShortVersionString': app_ver,
            'CFBundleSupportedPlatforms': ('MacOSX',),
            'CFBundleVersion': app_ver,
            'LSApplicationCategoryType': 'public.app-category.utilities',
            'LSArchitecturePriority': ('arm64', 'x86_64', 'i386')}, f)
    p = path.join(p, 'MacOS')
    makedirs(p, exist_ok=True)
    p = path.join(p, 'dwex')
    with open(p, 'wt') as f:
        f.write(f'#!{sys.executable}\nfrom dwex.__main__ import main\nmain()')
    os.chmod(p, 0o755)

def create_app_bundle(inst):
    try:
        try:
            app_ver = inst.config_vars['dist_version']
            create_app_bundle_under(app_ver, '/Applications')
        except OSError:
            makedirs('~/Applications', exist_ok=True)
            create_app_bundle_under(app_ver, '~/Applications')
    except Exception as exc:
        pass

#--------------------------------------

class my_install(install):
    def run(self):
        install.run(self)
        os_name = platform.system()
        if os_name == 'Windows':
            create_shortcut(self)
        elif os_name == 'Linux':
            register_desktop_app()
        elif os_name == 'Darwin':
            create_app_bundle(self)

# Pull the long desc from the readme
try:
    with open(path.join(path.abspath(path.dirname(__file__)), 'README.md')) as f:
        long_desc = f.read()          
except:
    long_desc = "GUI viewer for DWARF debug information"

setup(
    name='dwex',
    version='4.55',  # Sync with version in __main__
    packages=['dwex'],
    url="https://github.com/sevaa/dwex/",
    entry_points={"gui_scripts": ["dwex = dwex.__main__:main"]},
    cmdclass={'install': my_install},
    keywords = ['dwarf', 'debug', 'debugging', 'symbols', 'viewer', 'view', 'browser', 'browse', 'tree'],
    license="BSD-3-Clause",
    author="Seva Alekseyev",
    author_email="sevaa@sprynet.com",
    description="GUI viewer for DWARF debug information",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    python_requires=">=3.6.1",
    setup_requires=[],
    install_requires=['PyQt6', 'filebytes>=0.10.1', 'pyelftools>=0.32'] + (['pyobjc'] if platform.system() == 'Darwin' else []),
    platforms='any',
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Environment :: MacOS X :: Cocoa",
        "Environment :: Win32 (MS Windows)",
        "Environment :: X11 Applications :: Qt",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Software Development :: Debuggers"
    ]
)

