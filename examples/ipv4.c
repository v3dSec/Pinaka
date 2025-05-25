#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_ipv4(const char *ips[], int ip_count, unsigned char *decoded_shellcode)
{
    for (int i = 0; i < ip_count; i++)
    {
        unsigned int bytes[4];
        sscanf_s(ips[i], "%u.%u.%u.%u", &bytes[0], &bytes[1], &bytes[2], &bytes[3]);

        for (int j = 0; j < 4; j++)
        {
            decoded_shellcode[i * 4 + j] = (unsigned char)bytes[j];
        }
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (shellcode == NULL)
        return 1;

    decode_ipv4(encoded, shellcode_len / 4, (unsigned char *)shellcode);

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
