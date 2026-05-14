from pwn import *
from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes
import gmpy2
r = remote("shell.challs.cyberchallenge.it",9048)
n = []
c = []

for i in range(5):
    r.sendlineafter(b'> ',b'1')
    r.recvuntil(b'N: ')
    n.append(int(r.recvline().strip().decode()))
    r.recvuntil(b'Ciphertext: ')
    c.append(int(r.recvline().strip().decode()))

res,a = crt(n,c)
print(long_to_bytes(gmpy2.iroot(res,5)[0]).decode())

