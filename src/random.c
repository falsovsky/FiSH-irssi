#include "random.h"

#include <stdio.h>

int random_read (char* dest, size_t n)
{
    FILE* fp = fopen("/dev/urandom", "rb");

    if (fread(dest, 1, n, fp) != n) {
        return -1;
    }

    return 0;
}
