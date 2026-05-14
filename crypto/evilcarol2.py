from pwn import *
import hashlib
from Crypto.Cipher import AES
from sympy.ntheory import discrete_log
from Crypto.Util.number import getPrime, long_to_bytes , isPrime
r = remote("carol.challs.cyberchallenge.it", 9046)

r.recvuntil(b'p: ')
p = int(r.recvline().strip().decode())
r.recvuntil(b'pubA: ')
pubA = int(r.recvline().strip().decode())
r.recvuntil(b'pubB: ')
pubB = int(r.recvline().strip().decode())
r.recvuntil(b'flag: ')
flag = bytes.fromhex(r.recvline().strip().decode())
my_p = 2
i = 0
small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
while my_p.bit_length() < 1536:
    my_p *= small_primes[i%len(small_primes)]
    i += 1
k = 2
while not isPrime((k * my_p)+1):
    k += 1
my_p = (k * my_p)+1
r.sendlineafter(b'prime: ',str(my_p).encode())
r.sendlineafter(b'generator: ',str(2).encode())
r.sendlineafter(b'public value: ',str(0xFFFFFFFF + 1).encode())
r.sendlineafter(b'message: ',str(2).encode())

r.recvuntil(b'pubB: ')
my_pubB = int(r.recvline().strip().decode())
try:
    privB = discrete_log(my_p,my_pubB,2)
    print("SUCCESS")
    print(privB)
except:
    print("ERROR DISCRETE LOGARITHM")

shared_secret = pow(pubA,privB,p)  
key = hashlib.sha256(long_to_bytes(shared_secret)).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(flag))
r.interactive()
