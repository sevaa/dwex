from setuptools import setup
from setuptools.command.install import install, uninstall
import platform

class my_install(install):
    def run(self):
        install.run(self)
        #if platform.system() == 'Windows':
        #    from winsetup import create_shortcut
        #    create_shortcut()


setup(
    name='dwex',
    version='0.50',
    packages=['dwex',
        'dwex.elftools',
        'dwex.elftools.elf',
        'dwex.elftools.common',
        'dwex.elftools.dwarf',
        'dwex.elftools.construct',
        'dwex.elftools.construct.lib',
        'dwex.filebytes'],
    url="https://github.com/sevaa/dwex/",
    entry_points={"gui_scripts": ["dwex = dwex.__main__:main"]},
    cmdclass={'install': my_install},
    
    keywords = ['dwarf', 'debug', 'debugging', 'symbols', 'viewer', 'view', 'browser', 'browse', 'tree'],
    license="BSD",
    author="Seva Alekseyev",
    author_email="sevaa@sprynet.com",
    description="GUI viewer for DWARF debug information",
    long_description="GUI viewer for DWARF debug information",
    long_description_content_type="text/plain",
    python_requires=">=3.5",
    setup_requires=[],
    install_requires=['pyqt5'],
    platforms='any',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Environment :: MacOS X :: Cocoa",
        "Environment :: Win32 (MS Windows)",
        "Environment :: X11 Applications :: Qt",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Software Development :: Debuggers"
    ]
)


