#include <stdio.h>
#include "shellcode.h"

void rc4_decrypt(unsigned char *shellcode, unsigned char *key, int shellcode_len, size_t key_len)
{
    unsigned char s[256];

    int i, j, k;

    for (i = 0; i < 256; i++)
    {
        s[i] = i;
    }

    for (i = j = 0; i < 256; i++)
    {
        j = (j + s[i] + key[i % key_len]) % 256;

        unsigned char temp = s[i];

        s[i] = s[j];

        s[j] = temp;
    }

    for (i = j = k = 0; k < shellcode_len; k++)
    {
        i = (i + 1) % 256;

        j = (j + s[i]) % 256;

        unsigned char temp = s[i];

        s[i] = s[j];

        s[j] = temp;

        shellcode[k] ^= s[(s[i] + s[j]) % 256];
    }
}

int main()
{
    rc4_decrypt(shellcode, key, shellcode_len, key_len);

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
