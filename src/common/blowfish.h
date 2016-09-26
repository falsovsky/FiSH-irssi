#include <string.h>
#include <stdlib.h>
#include <openssl/blowfish.h>
#include "FiSH_version.h"

#ifdef HAVE_STDINT
    #include <stdint.h>
#else
    #ifdef HAVE_INTTYPES
        #include <inttypes.h>
    #endif
#endif

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)

int decrypt_string(const char *key, const char *str, char *dest, int len);
int encrypt_string(const char *key, const char *str, char *dest, int len);
void encrypt_key(const char *key, const char *clearKey, char *encryptedKey);
