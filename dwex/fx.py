from PyQt6.QtCore import QEventLoop
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontInfo, QFont

_bold_font = None

def bold_font():
    global _bold_font
    if not _bold_font:
        fi = QFontInfo(QApplication.font())
        _bold_font = QFont(fi.family(), fi.pointSize(), QFont.Weight.Bold)
    return _bold_font

# TODO: cancellation, progress indication
def wait_with_events(cond, timeout=100):
    loop = QEventLoop(QApplication.instance())
    while cond():
        loop.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, timeout)