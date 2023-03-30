#!/usr/bin/env python3
from pwn import *
import json
import base64
from codecs import decode
from binascii import unhexlify

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def decode_res(encoded, encoding_type):
    if encoding_type == "base64":
        return base64.b64decode(encoded).decode("utf-8")
    elif encoding_type == "hex":
        return bytes.fromhex(encoded).decode("utf-8")
    elif encoding_type == "rot13":
        return decode(encoded, "rot_13")
    elif encoding_type == "bigint":
        return unhexlify(encoded.replace("0x", "")).decode("utf-8")
    elif encoding_type == "utf-8":
        s = ""
        for c in encoded:
            s += chr(c)
        return s 

for i in range(0, 101):
    received = json_recv()

    if "flag" in received:
        print(received["flag"])
        break

    encoded = received["encoded"]
    encoding_type = received["type"]

    decoded = decode_res(encoded, encoding_type)	

    to_send = {
        "decoded": decoded
    }

    json_send(to_send)
