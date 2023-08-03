import hashlib, urllib, random, string, traceback, sys, os, platform
from urllib.request import urlopen

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

def make_exc_report(exc, tb, version, ctxt=None):
    while tb.tb_next:
        tb = tb.tb_next
    ss = traceback.extract_tb(tb)
    stack = traceback.extract_stack(tb.tb_frame)
    crashpoint = ss[0]
    locals = tb.tb_frame.f_locals

    report = type(exc).__name__ + ' at ' + os.path.basename(crashpoint.filename) + ':' + str(crashpoint.lineno) + "\n"
    report += "DWEX " + '.'.join(str(v) for v in version) + "\n"
    report += "Python " + sys.version + "\n"
    report +=  platform.platform() + "\n"
    from .cookie import cookie
    if cookie:
        report += "Cookie: " + cookie + "\n"
    report += get_crash_die_context(locals, ctxt=ctxt)
    report += "".join(traceback.format_exception_only(type(exc), exc)) + "\n"

    report += "PyStack:\n"
    stacklines = [se.name + ' (' + os.path.basename(se.filename) + ':' + str(se.lineno) + ")\n" for se in stack]
    report += "".join(stacklines[::-1]) + "\n"

    report += "PyLocals:\n" + ''.join(k + ": " + str(locals[k]) + "\n" for k in locals).replace("\n\n","\n")

    if ctxt:
        report += "\nPyContext:\n" + ''.join(k + ": " + str(ctxt[k]) + "\n" for k in ctxt).replace("\n\n","\n")

    return report

def report_crash(exc, tb, version, is_crash, ctxt=None):
    try:
        submit_report('[python][dwex][pyexception]%s' % ('[crash]' if is_crash else '',), make_exc_report(exc, tb, version, ctxt=ctxt))
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
        submit_report(exc, (0, 50))
