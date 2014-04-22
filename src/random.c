#include "random.h"

#include <stdio.h>

int random_read (unsigned char* dest, size_t n)
{
    FILE* fp = fopen("/dev/urandom", "rb");

    if (fp == NULL) {
        return -2;
    }

    if (fread(dest, 1, n, fp) != n) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}
