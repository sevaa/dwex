from PyQt6.QtCore import QEventLoop
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontInfo, QFont

_bold_font = None
_fixed_font = None

def bold_font():
    global _bold_font
    if not _bold_font:
        fi = QFontInfo(QApplication.font())
        _bold_font = QFont(fi.family(), fi.pointSize(), QFont.Weight.Bold)
    return _bold_font

def fixed_font():
    global _fixed_font
    if not _fixed_font:
        _fixed_font = QFont("Monospace")
        _fixed_font.setStyleHint(QFont.StyleHint.TypeWriter)
    return _fixed_font

# TODO: cancellation, progress indication
def wait_with_events(cond, timeout=100):
    loop = QEventLoop(QApplication.instance())
    while cond():
        loop.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, timeout)