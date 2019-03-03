#include <string.h>
#include <stdlib.h>
#include <openssl/blowfish.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "FiSH_version.h"
#ifdef HAVE_STDINT
    #include <stdint.h>
#else
    #ifdef HAVE_INTTYPES
        #include <inttypes.h>
    #endif
#endif

extern char *iniKey;

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)

int decrypt_string(const char *key, const char *str, char *dest, int len);
int encrypt_string(const char *key, const char *str, char *dest, int len);
void encrypt_key(const char *key, char *encryptedKey);

int decrypt_string_cbc(const char *key, const char *str, char *dest, int len);
int encrypt_string_cbc(const char *key, const char *str, char *dest, int len);

int b64_op(const unsigned char* in, int in_len, char *out, int out_len, int op);