from pwn import *

r = remote("rev-chall.challs.cyberchallenge.it",38211)

dict = ['0','1']

payload = "0b10000110100001101001001010101000111101100110100011011100110010001011111011101000110100000110011010111110110001000110011011100110111010001011111011100100011001101110110010111110111000001101100001101000111100100110011011100100101111100110100011101110011010001110010011001000101111101100111"
curr_score = 289

for i in range(500):
    for char in dict:
        curr = payload + char
        r.sendlineafter(b'flag:',curr.encode())
        r.recvuntil(b'rev_score = ')
        score = r.recvline().strip().decode()
        if int(score) > curr_score :
            payload = curr
            curr_score += 1
            break

print(payload)
