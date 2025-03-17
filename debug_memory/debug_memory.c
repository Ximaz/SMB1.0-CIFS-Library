#include <stdio.h>

void debug_memory(const void *ptr, size_t size)
{
    const unsigned char *byte_ptr = (const unsigned char *)ptr;

    for (size_t i = 0; i < size; i++)
        printf("%02X%c", byte_ptr[i], i < (size - 1) ? ' ' : 0);
}