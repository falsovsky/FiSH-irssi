#include "SHA256.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/sha.h>

void SHA256_memory (const char* buffer, size_t len, char* hash)
{
    SHA256((const unsigned char *)buffer, len, (unsigned char *)hash);
}

int sha_file (const char *filename, char* hash)
{
    char buf[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    const int bufSize = 32768;
    int bytesRead = 0;
    FILE *file;
    unsigned char *buffer;

    file = fopen(filename, "rb");
    if (!file) return 0;

    SHA256_Init(&sha256);
    buffer = malloc(bufSize);
    if (!buffer) return ENOMEM;
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final((unsigned char*)buf, &sha256);

    SHA256((const unsigned char *)buf, strlen(buf), (unsigned char *)hash);

    fclose(file);
    free(buffer);
    return 1;
}
