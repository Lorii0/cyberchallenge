from pwn import *
from Crypto.Util.Padding import pad
r = remote("predictable.challs.cyberchallenge.it",9034)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
r.sendlineafter(b'> ',b'4')
a= r.recvline().strip().split()
admin_iv = a[1][1:-2].decode()
admin_iv = bytes.fromhex(admin_iv)
r.sendlineafter(b'> ',b'1')
r.sendlineafter(b'username: ',b'negro')
a = r.recv().split()
login_token = a[3]
iv = a[3][:32].decode()
iv = bytes.fromhex(iv)
inp = pad(b"get_flag",16)
p = xor(xor(admin_iv,iv),inp)
r.sendline(b'2')
r.recv()
r.sendline(login_token)
r.recv()
r.sendline(p.hex().encode())
r.recvuntil(b"token: ")
command = r.recvline().strip().decode()
print(iv.hex())
print(command)
command = admin_iv.hex() + command[32:64]
print(admin_iv.hex())
print(command)
r.sendlineafter(b'> ',b'3')
r.recv()
r.sendline(command.encode())
r.interactive()