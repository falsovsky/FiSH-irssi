
#include "password.h"
#include "SHA256.h"

void key_from_password (
    const char* a_password,
    char* a_key)
{
    char digest[256/8]; // SHA 256 uses 256/8 bytes.
    int i;

    memset(digest, 0, sizeof(digest));
    SHA256_memory((char*)a_password, strlen(a_password), digest);

    for (i=0; i<40872; i++) {
      SHA256_memory(digest, 32, digest);
    }

    memcpy(a_key, digest, sizeof(digest));
}

void key_hash (
    const char* a_key,
    char* a_hash)
{
    char digest[256/8];
    int i;

    memcpy(digest, a_key, sizeof(digest));
    for (i=0; i<30752; i++) {
      SHA256_memory(digest, 32, digest);
    }

    memcpy(a_hash, digest, sizeof(digest));
}

