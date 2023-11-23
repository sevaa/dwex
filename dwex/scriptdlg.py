from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import *
from elftools.dwarf.locationlists import LocationParser

class ScriptDlg(QDialog):
    def __init__(self, win, sample_die):
        from sys import version_info
        QDialog.__init__(self, win, Qt.WindowType.Dialog)
        self.sample_die = sample_die
        ly = QVBoxLayout()
        ly.addWidget(QLabel("Provide a Python %d.%d expression for the \"die\" object:" % (version_info.major, version_info.minor), self))
        self.text = QPlainTextEdit(self)
        ly.addWidget(self.text)
        l = QLabel("<a href=\"https://github.com/sevaa/dwex/wiki/About-expressions\">See the guide</a>", self)
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
                env = make_execution_environment(self.sample_die)
            except Exception: #Our error - do not surface
                QDialog.accept(self)
                return

            try:
                eval(self.cond, env)
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
            
    def has_loclist():
        ver = die.cu.header.version
        def attr_is_loclist(attr):
            return (LocationParser._attribute_is_loclistptr_class(attr) and
                LocationParser._attribute_has_loc_list(attr, ver))
        g = (a for a in die.attributes if attr_is_loclist(die.attributes[a]))
        return bool(next(g, False))
            
    d = {'die' : die,
            'tag': 'user_%X' % (die.tag,) if isinstance(die.tag, int) else die.tag[7:],
            'attr': die.attributes,
            'has_attribute' : has_attribute,
            'has_loclist' : has_loclist}
    for k, a in die.attributes.items():
        d['user_%X' % (k,) if isinstance(k, int) else k[6:]] = a.value
    return d
            


    
        
