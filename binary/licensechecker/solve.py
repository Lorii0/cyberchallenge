#!/usr/bin/env python3
from pwn import *
import string
import os
os.environ["PORT"] = "38205"
os.environ["REMOTE"] = "licensechecker.challs.cyberchallenge.it"

bin_name = "./licensechecker"
context.aslr = False
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')
def conn():
    if args.GDB:
        print("AAAAAAAAAAAAAAA")
        return gdb.debug(elf.path,gdbscript='b main\nb *(main + 0x311)\nc')
    elif args.REMOTE:
        return remote("licensechecker.challs.cyberchallenge.it", 38204)
    else:
        return process(elf.path)

def main():
    r = conn()
    rev = b"\x49\x3e\x60\x22"
    for i in rev:
        print(hex(i),end =" - ")
        print(hex(i+65))
    r.recv()
    for i in range(4):
        print(chr(65+49+i))
    payload = b'7r\x8a7s\x7f7t\xa17u\x63'
    #payload = b'4A\x78AB\xf8AC\x71AD\x86'
    print(len(payload))
    print(payload)
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
