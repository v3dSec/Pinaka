#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "shellcode.h"

#pragma comment(lib, "advapi32.lib")

void aes_decrypt(unsigned char *shellcode, unsigned char *key, int shellcode_len, size_t key_len)
{
    HCRYPTPROV hProv;

    HCRYPTHASH hHash;

    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        exit(1);
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);

        exit(1);
    }

    if (!CryptHashData(hHash, (BYTE *)key, (DWORD)key_len, 0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(hProv, 0);

        exit(1);
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(hProv, 0);

        exit(1);
    }

    DWORD temp_len = (DWORD)shellcode_len;

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE *)shellcode, &temp_len))
    {
        CryptDestroyKey(hKey);

        CryptDestroyHash(hHash);

        CryptReleaseContext(hProv, 0);

        exit(1);
    }

    CryptDestroyKey(hKey);

    CryptDestroyHash(hHash);

    CryptReleaseContext(hProv, 0);
}

int main()
{
    aes_decrypt(shellcode, key, shellcode_len, key_len);

    printf("\nunsigned char shellcode[] = {");

    for (unsigned int i = 0; i < shellcode_len; i++)
    {
        if (i % 20 == 0)

            printf("\n\t");

        printf("0x%02x,", shellcode[i]);
    }

    printf("};\n");

    return 0;
}
