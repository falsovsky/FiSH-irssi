#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/sha.h>

void SHA256_memory(char *buf, const int len, const char *hash);
int sha_file(const char *filename, const char *hash);
