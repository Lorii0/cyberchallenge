#!/usr/bin/env python3
from Crypto.Hash import SHA3_384
import string
flag = "7b957b95daf0daf25dbf0312d87854284303dfe8f39ddfe801c117c0f01f7ccae013daf2dfe8636417c0dfe8bef3d17e5f97dfe8d878dfe85c615f97405602d6"
flag = bytes.fromhex(flag)
frags = [flag[i:i+2] for i in range(0,len(flag),2)]

dict= dict()
for i in string.printable[:-6]:
    a = SHA3_384.new(bytes([ord(i)])).digest()[:2]
    dict[a]=i

for i in frags:
    print(dict[i],end="")