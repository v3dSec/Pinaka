#include <stdio.h>
#include "shellcode.h"

void caesar_decrypt(unsigned char *shellcode, int key, int shellcode_len)
{
    for (int i = 0; i < shellcode_len; i++)
    {
        shellcode[i] -= key % 255;
    }
}

int main()
{
    caesar_decrypt(shellcode, key, shellcode_len);

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
