from pwn import *

r = remote("danceable.challs.cyberchallenge.it", 9036)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

r.sendlineafter(b'> ',b'1')
r.sendlineafter(b'? ',b"1"*32)
enc = r.recvline().strip().decode()
flag = xor(xor(bytes.fromhex(enc[:32]),bytes.fromhex(enc[32:64])),bytes.fromhex("1"*32))
print(flag.decode(),end="")
flag2 = xor(xor(bytes.fromhex(enc[:32]),bytes.fromhex(enc[64:96])),bytes.fromhex("1"*32))
print(flag2.decode())