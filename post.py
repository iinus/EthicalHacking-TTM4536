from urllib import request, parse
import hashlib
import binascii
import http.cookiejar

#passlist = open('../../src/rockyou.txt', 'r', encoding='utf-8', errors="ignore")
#passlist = passlist.readlines()

url = 'http://129.241.200.165'

flag = ""

values = {'flag' : flag
}

data = parse.urlencode(values).encode("utf-8")
req = request.Request(url, data=data)
with request.urlopen(req, data=data) as f:
    page = f.read()
    page = str(page)
    print(page)

if 'Invalid password!' not in page:
    print ('\033[92m' + "[*] flag found: " + flag )