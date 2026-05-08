from pwn import *

r = remote("desoracle.challs.cyberchallenge.it",9035)

key = b"0101010101010101"
r.sendlineafter(b'> ',b'2')
r.recv()
r.sendline(key)
flag = r.recvline().strip()
r.sendlineafter(b'> ',b'1')
r.recv()
r.sendline(flag)
r.recv()
r.sendline(key)
flag = r.recvline().strip()
print(bytes.fromhex(flag.decode()))
