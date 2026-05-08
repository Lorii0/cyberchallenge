from pwn import * 

hex_output = "43A1528AB71BA1685FB11A86F593CCC26CAFDCAD037BD1D05F314E2C5313E0C837BE"

bin_output = bin(int(hex_output,16))[2:].zfill(len(hex_output)*4)

bin_bytes = [bin_output[i:i+8] for i in range(0,len(bin_output),8)]

for i in range(len(bin_bytes)):
    bin_bytes[i] = rol(bin_bytes[i],i%8,8)

flag = ""
for i in range(len(bin_bytes)):
    a = int(bin_bytes[i],2)
    flag += chr(a)

print(flag)