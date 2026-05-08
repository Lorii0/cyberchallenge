from pwn import *

r = remote("piecewise.challs.cyberchallenge.it",9110)

while 1:
    req = r.recvline().decode().strip()
    if 'empty line' in req:
        r.send(b'\n')
    else:
        match= re.search(r'-?\d+', req)
        num = int(match.group())
        if '32-bit' in req:
            if 'big-endian' in req:
                r.send(p32(num,endian="big"))
            else:
                r.send(p32(num))
        else:
            if 'big-endian' in req:
                r.send(p64(num,endian="big"))
            else:
                r.send(p64(num))
    print(r.recvline())

r.interactive()
