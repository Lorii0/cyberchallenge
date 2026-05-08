from Crypto.Util.number import long_to_bytes
from pwn import *

r = remote("oracle.challs.cyberchallenge.it", 9041)
r.recvuntil(b'Encrypted flag: ')
c = int(r.recvline().strip().decode())
r.sendlineafter(b'> ',b'1')
r.sendlineafter(b'Plaintext > ',b'2')
r.recvuntil(b'Encrypted: ')
enc = int(r.recvline().strip().decode())
r.sendlineafter(b'> ',b'2')
r.sendlineafter(b'Ciphertext > ',str(c*enc).encode())
r.recvuntil(b'Decrypted: ')
flag = int(r.recvline().strip().decode())//2
print(long_to_bytes(flag))
r.interactive()