#!/usr/bin/env python3
from pwn import *

found_bytes = b""
bad_bytes = b""

for i in range(0, 0xFF):
    p = process("./bellcode")
    payload = bytes([i])
    p.sendline(payload)
    response = p.recvall()
    if b"Try harder" not in response: 
        found_bytes += payload
    else:
        bad_bytes += payload

print("GOOD CHARS:")
print(found_bytes)
print("BAD CHARS:")
print(bad_bytes)