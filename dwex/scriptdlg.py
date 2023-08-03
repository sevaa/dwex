from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *
from sys import version_info
import webbrowser

class ScriptDlg(QDialog):
    def __init__(self, win, sample_die):
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.sample_die = sample_die
        ly = QVBoxLayout()
        ly.addWidget(QLabel("Provide a Python %d.%d expression for the \"die\" object:" % (version_info.major, version_info.minor), self))
        self.text = QPlainTextEdit(self)
        ly.addWidget(self.text)
        l = QLabel("<a href=\"https://github.com/sevaa/dwex/blob/master/docs/expressions.md\">See the guide</a>", self)
        l.linkActivated.connect(self.on_see_guide)
        ly.addWidget(l)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel, Qt.Orientation.Horizontal, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        ly.addWidget(buttons)
        self.setWindowTitle('Condition')
        self.setLayout(ly)

    def on_see_guide(self, link):
        try:
            webbrowser.open(link, new=0, autoraise=True)
        except:
            pass

    def accept(self):
        self.py = self.text.document().toPlainText()
        if not self.py:
            QMessageBox(QMessageBox.Icon.Warning, "Error",
                "Please provide a Python expression that inspects the \"die\" object.", QMessageBox.StandardButton.Ok, self).show()
        else:
            try:
                self.cond = compile(self.py, 'inline', 'eval')
            except Exception as exc:
                QMessageBox(QMessageBox.Icon.Warning, "Python error",
                    "Python syntax error: " + format(exc), QMessageBox.StandardButton.Ok, self).show()
                return
            try:
                eval(self.cond, {'die' : self.sample_die, 'has_attribute' : lambda f:True})
            except Exception as exc:
                QMessageBox(QMessageBox.Icon.Warning, "Python error",
                    "Python execution error: " + format(exc), QMessageBox.StandardButton.Ok, self).show()
                return
            
            QDialog.accept(self)
            


    
        
