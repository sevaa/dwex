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

def make_exc_report(exc, tb, version):
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
    report += "".join(traceback.format_exception_only(type(exc), exc)) + "\n"

    report += "PyStack:\n"
    stacklines = [se.name + ' (' + os.path.basename(se.filename) + ':' + str(se.lineno) + ")\n" for se in stack]
    report += "".join(stacklines[::-1]) + "\n"

    report += "PyLocals:\n" + ''.join(k + ": " + str(locals[k]) + "\n" for k in locals).replace("\n\n","\n")
    return report

def report_crash(exc, tb, version):
    try:
        submit_report('[crash][python][dwex][pyexception]', make_exc_report(exc, tb, version))
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
