#include <stdio.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/sha.h>

// SHA-256 a block of memory
void SHA256_memory(unsigned char *buf, int len, unsigned char *hash)
{
    SHA256(buf, len, hash);
}


// SHA-256 a file, return 1 if ok
int sha_file(unsigned char *filename, unsigned char *hash)
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

    SHA256(buf, strlen(buf), hash);

    fclose(file);
    free(buffer);
    return 1;
}
