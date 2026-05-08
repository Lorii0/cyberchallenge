from pwn import *
import string
r = remote("padding.challs.cyberchallenge.it", 9030)

count = 31
flag = ""  
r.recv()
for pos in range(32):
    for i in string.printable[:-6]:
        payload = "a"*count + flag + i + "a"*count
        print(payload)
        r.sendline(payload)
        r.recvuntil(b'password: ')
        tmp = r.recvline().strip()
        if tmp[32:64] == tmp[96:128]:
            print(f"found char: {i}")
            count -= 1
            flag += i
            break
    print(f"current: {flag}")
