#ifndef SHA256_H_
#define SHA256_H_

#include <stddef.h>

void SHA256_memory (const char* buffer, size_t len, char* hash);

// SHA-256 a file, return 1 if ok
int sha_file (const char *filename, char* hash);

#endif // SHA256_H_
