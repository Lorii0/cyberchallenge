from Crypto.Util.number import long_to_bytes
from pwn import *
import math

r = remote("oracle.challs.cyberchallenge.it", 9044)
r.recvuntil(b'Encrypted flag: ')
c = int(r.recvline().strip().decode())

e = 65537
m1 = 9
m2 = 17

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

n = math.gcd(pow(m1,e)-enc1,pow(m2,e)-enc2)
for i in range(2,2000):
    while n % i == 0:
        n = n // i
myval = pow(n-1,e,n)
inv = pow(n-1,-1,n)
r.sendlineafter(b'> ',b'2')
payload = (c*myval) % n
r.sendlineafter(b'Ciphertext > ',str(payload))
r.recvuntil(b'Decrypted: ')
flag = int(r.recvline().strip().decode())
flag = (flag * inv) % n
print(long_to_bytes(flag))
r.interactive()