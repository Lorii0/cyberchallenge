from pwn import *

r = remote("padding.challs.cyberchallenge.it",9033)
r.recvuntil(b'flag\n')
c = r.recvline().strip().decode()
enc = bytes.fromhex(c)
blocks = [enc[i:i+16] for i in range(0,len(enc),16)]
flag = b""

for b in range(3,len(blocks)):
    prev = blocks[b-1]
    curr = blocks[b]
    I = bytearray(16)
    plain = bytearray(16)
    for i in range(15,-1,-1):
        pad = 16-i
        for ch in range(256):
            guess = bytearray(16)
            for j in range(15,i,-1):
                guess[j] = I[j] ^ pad
            guess[i]= ch
            payload = guess + curr
            payload = payload.hex().encode()
            r.sendlineafter(b"? ",payload)
            res = r.recvline()

            if b'strong' in res:
                I[i] = ch ^ pad
                plain[i]= I[i] ^ prev[i]
                print(plain)
                break

    flag += plain

print(flag)