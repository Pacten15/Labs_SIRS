#!/usr/bin/python3
import sys
import json
import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

if len(sys.argv) < 3:
    print("Argument(s) missing!", file=sys.stderr)
    print(f"Usage: python3 {sys.argv[0]} <file.json> <privateRSA.key>", file=sys.stderr)
    exit(1)

# Try open/create JSON file
try: doc = open(sys.argv[1], 'w')
except IOError:
    print(f"File `{sys.argv[1]}' could not be opened.", file=sys.stderr)
    exit(1)

# Try read RSA private key
try:
    priv = open(sys.argv[2], 'rb')
    key = RSA.import_key(priv.read())
    pkcs = pkcs1_15.new(key)
except IOError:
    print(f"File `{sys.argv[2]}' could not be opened.", file=sys.stderr)
    doc.close()
    exit(1)

data = {}

data['header']  = {}
data['header']['title']   = 'Age of Ultron'
data['header']['author']  = 'Ultron'
data['header']['version'] = 2
data['header']['tags']    = ['robot', 'autonomy']

data['body']    = "I had string but now I'm free"
data['status']  = 'published'

message = json.dumps(data).encode()
h = SHA256.new(message)
sig = pkcs.sign(h)

data['__SIGN'] = base64.b64encode(sig).decode()

json.dump(data, doc, indent=4)
priv.close()
doc.close()
