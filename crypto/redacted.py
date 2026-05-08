from Crypto.Cipher import AES

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

partialkey = b"yn9RB3Lr43xJK2"
c2 = bytes.fromhex("78c670cb67a9e5773d696dc96b78c4e0")
c1 = b""
p2 = b"very unbreakable"
p1 = b"AES with CBC is "
ch1 = bytes.fromhex("c5")
ch2 = bytes.fromhex("d49e")
ok = True
key = b""
for i in range(256):
    if ok == False:
        break
    for j in range(256):
        k = partialkey + bytes([i]) + bytes([j])
        aes = AES.new(k, AES.MODE_ECB)
        i2 = aes.decrypt(c2)
        c = xor(i2,p2)
        if c.startswith(ch1) and c.endswith(ch2):
            print("CORRECT KEY")
            key = k
            c1=c
            print(key)
            ok = False
            break

i1 = aes.decrypt(c1)
iv = xor(i1,p1)
print(iv.decode())