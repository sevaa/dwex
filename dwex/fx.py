from PyQt6.QtCore import Qt, QEventLoop
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontInfo, QFont, QBrush

_bold_font = None
_fixed_font = None
blue_brush = QBrush(Qt.GlobalColor.blue)
ltgrey_brush = QBrush(Qt.GlobalColor.lightGray)

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

# Doesn't quite work for the delay on tree expansion :( TODO: timer checks before lighting up this
class WaitCursor():
    def __enter__(self):
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

    def __exit__(self, *args):
        QApplication.restoreOverrideCursor()

class ArrowCursor():
    def __enter__(self):
        QApplication.restoreOverrideCursor()

    def __exit__(self, *args):
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
