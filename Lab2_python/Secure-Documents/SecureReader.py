#!/usr/bin/python3
import sys
import json
import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

if len(sys.argv) < 3:
    print("Argument(s) missing!", file=sys.stderr)
    print(f"Usage: python3 {sys.argv[0]} <file.json> <publicRSA.key>", file=sys.stderr)
    exit(1)

# Try open/create JSON file
try: doc = open(sys.argv[1], 'r')
except IOError:
    print(f"File `{sys.argv[1]}' could not be opened.", file=sys.stderr)
    exit(1)

# Try read RSA private key
try:
    priv = open(sys.argv[2], 'rb')
    key = RSA.import_key(priv.read())
    pkcs = pkcs1_15.new(key)
    priv.close()
except IOError:
    print(f"File `{sys.argv[2]}' could not be opened.", file=sys.stderr)
    doc.close()
    exit(1)

data = json.load(doc)
doc.close()

sig = base64.b64decode(data['__SIGN'].encode())
data.pop('__SIGN', None)

message = json.dumps(data).encode()
h = SHA256.new(message)

# Verify signature
try: pkcs.verify(h, sig)
except (ValueError, TypeError):
    print(f"The signature is not valid.", file=sys.stderr)
    exit(1)

header = data['header']
print(f"JSON object: {data}\n")
print(f"Document header:")
print(f"  Title:   {header['title']}")
print(f"  Author:  {header['author']}")
print(f"  Version: {header['version']}")
print(f"  Tags: {header['tags']}")
print(f"Document body: {data['body']}")
print(f"Document status: {data['status']}")
