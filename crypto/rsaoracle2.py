from Crypto.Util.number import long_to_bytes
from pwn import *
import math

r = remote("oracle.challs.cyberchallenge.it", 9042)
r.recvuntil(b'Encrypted flag: ')
c = int(r.recvline().strip().decode())

e = 65537
m1 = 13
m2 = 17
m3 = 19

#------------ m1
r.sendlineafter(b'> ',b'1')
r.sendlineafter(b'Plaintext > ',str(m1).encode())
r.recvuntil(b'Encrypted: ')
enc1 = int(r.recvline().strip().decode())

#------------ m2
r.sendlineafter(b'> ',b'1')
r.sendlineafter(b'Plaintext > ',str(m2).encode())
r.recvuntil(b'Encrypted: ')
enc2 = int(r.recvline().strip().decode())

#------------ m3
r.sendlineafter(b'> ',b'1')
r.sendlineafter(b'Plaintext > ',str(m3).encode())
r.recvuntil(b'Encrypted: ')
enc3 = int(r.recvline().strip().decode())

n = math.gcd(pow(m1,e)-enc1,pow(m2,e)-enc2,pow(m3,e)-enc3)
myval = pow(n-1,e,n)
inv = pow(n-1,-1,n)
r.sendlineafter(b'> ',b'2')
r.sendlineafter(b'Ciphertext > ',str(c*myval))
r.recvuntil(b'Decrypted: ')
flag = int(r.recvline().strip().decode())
flag = (flag * inv) % n
print(long_to_bytes(flag))
r.interactive()