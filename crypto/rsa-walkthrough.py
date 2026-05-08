from Crypto.Util.number import bytes_to_long
from pwn import *
r = remote("rsa.challs.cyberchallenge.it",9040)
e=65537
# --------- level1
r.recvuntil(b"p = ")
p = int(r.recvline().strip().decode())
r.recvuntil(b"q = ")
q = int(r.recvline().strip().decode())
r.recv()
r.sendline(str(p*q))

# --------- level2

message=b"This is the plaintext"
r.recv()
r.sendline(str(bytes_to_long(message)))

# --------- level3

r.recvuntil(b"p = ")
p = int(r.recvline().strip().decode())
r.recvuntil(b"q = ")
q = int(r.recvline().strip().decode())
r.recvuntil(b"m = ")
m = int(r.recvline().strip().decode())
r.recv()
r.sendline(str(pow(m,e,p*q)))

# --------- level4

r.recvuntil(b"p = ")
p = int(r.recvline().strip().decode())
r.recvuntil(b"q = ")
q = int(r.recvline().strip().decode())
r.recv()
r.sendline(str((p-1)*(q-1)))
r.recv()
d = pow(e,-1,(p-1)*(q-1))
r.sendline(str(d))

# --------- level5

r.recvuntil(b"p = ")
p = int(r.recvline().strip().decode())
r.recvuntil(b"q = ")
q = int(r.recvline().strip().decode())
r.recvuntil(b"c = ")
c = int(r.recvline().strip().decode())
r.recv()
d = pow(e,-1,(p-1)*(q-1))
r.sendline(str(pow(c,d,p*q)))
r.interactive()
