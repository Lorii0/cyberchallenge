#!/usr/bin/env python3
from pwn import *

bin_name = "./canvas_patched"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='start\nn 11\n')
    elif args.REMOTE:
        return remote("canvas.challs.cyberchallenge.it", 9603)
    else:
        return process(elf.path)

def main():
    r = conn()
    pop_rdi = 0x16b3
    pop_rsi_r15 = 0x16b1

    r.interactive()

if __name__ == "__main__":
    main()
