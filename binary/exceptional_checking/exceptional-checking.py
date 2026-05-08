from pwn import *

context.arch = 'amd64'

# Load the ORIGINAL 940 bytes from IDA
with open("shellcode.bin", "rb") as f:
    data = bytearray(f.read())

offset = 0
layer = 1

print("[*] Starting Automated Unpacker...")

while True:
    trap_found = False
    
    # The author adds 0 to 2 bytes of junk instructions before the trap.
    # We scan a small window ahead of our current execution offset.
    for i in range(offset, offset + 5):
        # Signature: 0x41 0xBB [4 bytes] 0xCC
        if data[i] == 0x41 and data[i+1] == 0xBB and data[i+6] == 0xCC:
            
            # 1. Extract the Key
            key_bytes = data[i+2:i+6]
            key = u32(key_bytes)
            print(f"[+] Layer {layer} defeated! Key: {hex(key)}")
            
            # 2. Decrypt the entire buffer with the new key
            for j in range(0, len(data), 4):
                chunk = data[j:j+4]
                if len(chunk) == 4:
                    v = u32(chunk)
                    data[j:j+4] = p32(v ^ key)
            
            # 3. Advance our execution offset past the int 3 (0xCC)
            offset = i + 7
            layer += 1
            trap_found = True
            break # Break the search window, restart the while loop
            
    # If we didn't find the 41 BB ... CC signature, we hit the real code!
    if not trap_found:
        print(f"\n[!] No more traps found. Bottom reached at Layer {layer-1}.")
        break

# Slice off ALL the accumulated garbage traps using our final offset
clean_shellcode = data[offset:]

print("\n[*] Final Decrypted Payload Assembly:")
print("-" * 60)
print(disasm(clean_shellcode))

# Optional: Save it so you can drop it into IDA
with open("final_naked_shellcode.bin", "wb") as f:
    f.write(clean_shellcode)