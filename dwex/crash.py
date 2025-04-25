import hashlib, urllib, random, string, traceback, sys, os, platform
from urllib.request import urlopen
# No dependencies on the rest of the app, and keep it that way

_binary_desc = None

def set_binary_desc(s):
    global _binary_desc
    _binary_desc = s

def submit_report(subj, body):
    try:
        secret = "jkaweliop3jka;lswmn12"
        chars = string.ascii_letters + string.digits
        id = ''.join(random.choice(chars) for x in range(50))
        h = hashlib.sha1()
        h.update((id + secret).encode('utf-8'))
        reqdata = {'to': "support@yarxi.ru",
		        'from': "\"DWEX\"<support@yarxi.ru>",
		        'subj': subj,
		        'body': body,
		        'id': id,
		        'hash': h.digest().hex()}
        reqdata = urllib.parse.urlencode(reqdata).encode('utf-8')
        urlopen('http://yarxi.ru/mobile/mail.php', reqdata).info()
    except Exception as exc:
        pass

def get_crash_die(locals):
    if "self" in locals and hasattr(locals['self'], 'die'):
        return locals['self'].die
    elif "die" in locals:
        return locals['die']
    else:
        return False

def get_crash_die_context(locals, ctxt = None):
    s = ''
    try:
        crash_die = get_crash_die(locals)
        if not crash_die and ctxt:
            crash_die = get_crash_die(ctxt)
        if crash_die:
            top = crash_die.cu.get_top_DIE()
            if top:
                if 'DW_AT_language' in top.attributes:
                    s += "Source language: 0x%x\n" % (top.attributes['DW_AT_language'].value,)
                if 'DW_AT_producer' in top.attributes:
                    s += "Producer: %s\n" % (top.attributes['DW_AT_producer'].value.decode('utf-8', errors='ignore'),)
    except:
        pass
    return s

def make_exc_report(exc, tb, version, catchpoint, ctxt=None):
    global _binary_desc
    tracebacks = []
    while tb.tb_next:
        tracebacks.insert(0, tb) # Innermost in the beginning of the list
        tb = tb.tb_next
    ss = traceback.extract_tb(tb)
    innermost_stack = traceback.extract_stack(tb.tb_frame)
    crashpoint = ss[0]
    locals = tb.tb_frame.f_locals

    report = type(exc).__name__ + ' at ' + os.path.basename(crashpoint.filename) + ':' + str(crashpoint.lineno) + "\n"
    if catchpoint:
        from inspect import getframeinfo
        fi = getframeinfo(catchpoint)
        report += "Caught %s@%s:%d\n" % (fi.function, os.path.basename(fi.filename), fi.lineno)
    report += "DWEX " + '.'.join(str(v) for v in version) + "\n"
    report += "Python " + sys.version + "\n"
    report += "System: " + platform.platform() + "\n"
    try:
        import elftools
        if hasattr(elftools, '__version__'):
            report += "Pyelftools: " + elftools.__version__ + "\n"
    except ImportError:
        pass
    if _binary_desc:
        report += "Binary: " + _binary_desc + "\n"
    try:
        from .cookie import cookie
    except ImportError:
        cookie = False
    if cookie:
        report += "Cookie: " + cookie + "\n"
    report += get_crash_die_context(locals, ctxt=ctxt)
    report += "".join(traceback.format_exception_only(type(exc), exc)) + "\n"

    report += "PyStack_v3:\n"
    def module_prefix(se):
        p = os.path.dirname(se.filename).split(os.path.sep)
        if 'elftools' in p:
            return 'pyelftools/'
        elif 'dwex' in p:
            return 'dwex/'
        return ''
    def make_stackline(se):
        return se.name + '@' + module_prefix(se) + os.path.basename(se.filename) + ':' + str(se.lineno) + "\n"
    def make_stack_dump(stack):
        return [make_stackline(se) for se in stack[::-1]]
    def make_traceback_dump(tb):
        return "-\n"+"".join(make_stack_dump(traceback.extract_stack(tb.tb_frame)))

    report += "".join(make_stack_dump(innermost_stack))
    # More tracebacks
    report += "".join(make_traceback_dump(tb) for tb in tracebacks[1:])
    report += "\n"

    report += "PyLocals:\n" + ''.join(k + ": " + str(locals[k]) + "\n" for k in locals).replace("\n\n","\n")

    if ctxt:
        report += "\nPyContext:\n" + ''.join(k + ": " + str(ctxt[k]) + "\n" for k in ctxt).replace("\n\n","\n")

    return report

def report_crash(exc, tb, version, catchpoint = None, ctxt=None):
    try:
        subj = '[python][dwex][pyexception]'
        if not catchpoint:
            subj += '[crash]'
        submit_report(subj, make_exc_report(exc, tb, version, catchpoint, ctxt=ctxt))
    except Exception:
        pass

if __name__ == "__main__":
    try:
        def bar():
            i=0
            a=1
            a /=i

        def foo():
            bar()

        foo()
    except Exception as exc:
        from inspect import currentframe
        report_crash(exc, exc.__traceback__, (0, 50), currentframe())
