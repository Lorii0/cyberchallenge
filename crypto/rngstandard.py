from pwn import *
from randcrack import RandCrack

rc = RandCrack()

r= remote("srng.challs.cyberchallenge.it",9064)

for i in range(624):
    r.recv()
    r.sendline(b'2')
    r.recvuntil(b'My number was ')
    num = r.recvline().strip().decode()
    rc.submit(int(num))
    #print(f"{i}) : {num}")

next_number = rc.predict_getrandbits(32)
print(f"NUMERO PREDICTATO : {next_number}")
r.recv()
r.sendline(b'1')
r.sendline(p32(next_number))
r.interactive()