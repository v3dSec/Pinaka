#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_jigsaw(unsigned char jigsaw[], int positions[], unsigned char shellcode[], int shellcode_len)
{
    int position;

    for (int idx = 0; idx < shellcode_len; idx++)
    {
        position = positions[idx];

        shellcode[position] = jigsaw[idx];
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_jigsaw(encoded, positions, shellcode, shellcode_len);

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
