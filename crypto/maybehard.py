from pwn import *
from math import gcd
p = remote("maybehard.challs.cyberchallenge.it", 9049)

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'> ',b'2')
tmp1 = int(p.recvline().strip().decode())
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'> ',b'4')
tmp2 = int(p.recvline().strip().decode())

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'> ',b'3')
tmp3 = int(p.recvline().strip().decode())
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'> ',b'9')
tmp4 = int(p.recvline().strip().decode())

n = gcd(pow(tmp1,2)-tmp2,pow(tmp3,2)-tmp4)
print(n)
l = 0
r = n
mult = tmp1
p.sendlineafter(b'> ',b'1')
flag = int(p.recvline().strip().decode())
payload = flag

while r != l:
    mid = (r+l)//2
    payload = (mult * payload) % n    
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'> ',str(payload).encode())
    res = int(p.recvline().strip().decode())
    print(res)
    if  res % 2 == 0:
        r = mid
    else:
        l = mid 

print(r,l)
