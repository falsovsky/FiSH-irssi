#include <string.h>
#include <stdlib.h>
#include <openssl/blowfish.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
//#include "FiSH_version.h"
#ifdef HAVE_STDINT
    #include <stdint.h>
#else
    #ifdef HAVE_INTTYPES
        #include <inttypes.h>
    #endif
#endif

int decrypt_string_cbc(const char *key, const char *str, char *dest, int len);
int encrypt_string_cbc(const char *key, const char *str, char *dest, int len);
