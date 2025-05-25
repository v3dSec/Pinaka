#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"

void decode_jenkins(const int *encoded, size_t encoded_len, unsigned char *decoded_shellcode)
{
    unsigned long lookup_table[256];

    for (int i = 0; i < 256; i++)
    {
        unsigned long hash = 0;
        unsigned char key = (unsigned char)i;

        hash += key;
        hash += (hash << 10);
        hash ^= (hash >> 6);
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);

        lookup_table[i] = hash;
    }

    for (size_t i = 0; i < encoded_len; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            if (lookup_table[j] == (unsigned long)encoded[i])
            {
                decoded_shellcode[i] = (unsigned char)j;
                break;
            }
        }
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_jenkins(encoded, shellcode_len, (unsigned char *)shellcode);

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
