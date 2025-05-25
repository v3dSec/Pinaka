#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_binary(const char *binary[], unsigned char *decoded_shellcode, size_t binary_len)
{
    for (size_t i = 0; i < binary_len; i++)
    {
        int value = 0;
        for (int j = 0; j < 8; j++)
        {
            value = value * 2 + (binary[i][j] - '0');
        }
        decoded_shellcode[i] = (unsigned char)value;
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (shellcode == NULL)
        return 1;

    decode_binary(encoded, (unsigned char *)shellcode, shellcode_len);

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
