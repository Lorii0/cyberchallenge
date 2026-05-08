from pwn import *

r = remote("notadmin.challs.cyberchallenge.it", 9032)

r.sendlineafter(b'> ', b'1')

name = b"a"
r.sendlineafter(b'username: ', name)

r.recvuntil(b'login token: ')
token_hex = r.recvline().strip()

raw_token = bytearray.fromhex(token_hex.decode())

iv = raw_token[0:16]
ct = raw_token[16:]

actual = b"usr=a;is_admin=0"
target = b"usr=a;is_admin=1"

modified_iv = xor(iv, xor(actual, target))

payload = modified_iv + ct

r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'token: ', payload.hex().encode())

print(r.recv().decode())