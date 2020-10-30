#!/usr/bin/python3
from operator import xor

msg = [11,29,27,25,10,21,1,0,23,10,17,12,13,8]
decrypted = ""
for key in msg:
    decrypted += chr(xor(ord('x'),key))
print(decrypted)
