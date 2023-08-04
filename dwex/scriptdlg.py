from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *

class ScriptDlg(QDialog):
    def __init__(self, win, sample_die):
        from sys import version_info
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
            import webbrowser
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
                eval(self.cond, make_execution_environment(self.sample_die))
            except Exception as exc:
                mb = QMessageBox(QMessageBox.Icon.Question, "Python error",
                    "Python execution error (%s) on a sample DIE. Use anyway?\n\n%s" % (type(exc).__name__, format(exc)),
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No, self)
                mb.setEscapeButton(QMessageBox.StandardButton.No)
                if mb.exec() == QMessageBox.StandardButton.No:
                    return
            
            QDialog.accept(self)

def make_execution_environment(die):
    def has_attribute(func):
        for k in die.attributes:
            if func(k, die.attributes[k].value, die.attributes[k].form):
                return True
            
    d = {'die' : die,
            'tag': die.tag,
            'attr': die.attributes,
            'has_attribute' : has_attribute}
    for k, a in die.attributes.items():
        d[k] = a.value
    return d
            


    
        
