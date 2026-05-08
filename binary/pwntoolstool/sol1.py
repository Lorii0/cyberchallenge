from pwn import *
import ast
r = remote("software-17.challs.olicyber.it", 13000)

r.recvline()
r.sendline(b'a')

for i in range(10):
    r.recvuntil(b'questi numeri\n' )
    array = r.recvline().strip().decode()
    r.recv()
    array = ast.literal_eval(array)
    print(sum(array))
    r.sendline(str(sum(array)).encode())

print(r.recv(100))