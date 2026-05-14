from pwn import *
import math
from Crypto.Util.number import long_to_bytes

r = remote("paas.challs.cyberchallenge.it", 9047)
e = 65537
r.sendlineafter(b'> ',b'1')
r.recvuntil(b'N: ')
flag_n = int(r.recvline().strip().decode())
r.recvuntil(b'Ciphertext: ')
c = int(r.recvline().strip().decode())

def decrypt(n):
    p = math.gcd(n,flag_n)
    if p == 1:
        return
    if p == flag_n:
        return
    q = flag_n // p
    tot = (q-1)*(p-1)
    d = pow(e,-1,tot)
    flag = pow(c,d,flag_n)
    print(long_to_bytes(flag).decode())
while True:
    try:
        r.sendlineafter(b'> ',b'2')
        r.sendlineafter(b'> ',b'2')
        r.recvuntil(b'N: ')
        n = int(r.recvline().strip().decode())
        decrypt(n)
    except:
        break