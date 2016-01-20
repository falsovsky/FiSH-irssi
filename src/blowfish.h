#include <string.h>
#include <stdlib.h>

extern char *iniKey;

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)

int decrypt_string(const char *key, const char *str, char *dest, int len);
int encrypt_string(const char *key, const char *str, char *dest, int len);
void encrypt_key(const char *key, char *encryptedKey);
