#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_octal(const char *octal[], size_t octal_len, unsigned char *decoded_shellcode)
{
    for (size_t i = 0; i < octal_len; i++)
    {
        int value = 0;
        for (int j = 0; j < 3; j++)
        {
            value = value * 8 + (octal[i][j] - '0');
        }
        decoded_shellcode[i] = (unsigned char)value;
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (shellcode == NULL)
        return 1;

    decode_octal(encoded, shellcode_len, (unsigned char *)shellcode);

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
