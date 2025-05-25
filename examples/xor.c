#include <stdio.h>
#include "shellcode.h"

void xor_decrypt(unsigned char *shellcode, unsigned char *key, int shellcode_len, size_t key_len)
{
    for (int i = 0; i < shellcode_len; i++)
    {
        shellcode[i] ^= key[i % key_len];
    }
}

int main()
{
    xor_decrypt(shellcode, key, shellcode_len, key_len);

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
