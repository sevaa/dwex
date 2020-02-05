import hashlib, urllib, random, string

def httpmail(subj, body):
    try:
        MAIL_SECRET = "jkaweliop3jka;lswmn12"
        chars = string.ascii_letters + string.digits
        id = ''.join(random.choice(chars) for x in range(50))
        reqdata = {"to": "support@yarxi.ru",
		        "from": "\"DWEX Python\"<support@yarxi.ru>",
		        "subj": subj,
		        "body": body,
		        "id": id,
		        "hash": hashlib.sha1(id + MAIL_SECRET)}
        urllib.request.urlopen('http://www.yarxi.ru/mobile/mail.php').info()
    except:
        pass

def report_crash(exc):
    try:
        report = ""
        httpmail('[crash][python][dwex]', report)
    except:
        pass
