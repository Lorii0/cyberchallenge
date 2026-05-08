from pwn import *
import string

r = remote("benchmark.challs.cyberchallenge.it",9031)

flag = "CCIT{s1d3_ch4nn3ls_r_c00l"

ok = True
for i in range (200):
    if ok == False:
        break
    max = -1
    maxn = ""
    ok = True
    for i in string.printable[:-6]:
        payload = flag + i
        r.sendlineafter(b'check:\n',payload.encode())
        t = r.recvline().decode()
        if "Correct" in t:
            flag += "}\n\n\n"
            print(flag)
            ok = False
            break
        t = int(t.split()[4])
        if t>max:
            max=t
            maxn=i
    flag+=maxn
    print(flag)