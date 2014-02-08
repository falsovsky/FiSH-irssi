// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#include "fish2/noop.h"

#include <stdlib.h>
#include <string.h>

int fish2_noop_encrypt (
    const char* key,
    const char* plaintext,
    size_t n,
    char** ciphertext,
    size_t* ciphersize)
{
    *ciphertext = (char*)malloc(n);

    if (*ciphertext == NULL) {
        return -1;
    }

    memcpy(ciphertext, plaintext, n);

    if (ciphersize) {
        *ciphersize = n;
    }

    return 0;
}

int fish2_noop_decrypt (
    const char* key,
    const char* ciphertext,
    size_t n,
    char** plaintext,
    size_t* plainsize)
{
    *plaintext = (char*)malloc(n);

    if (*plaintext == NULL) {
        return -1;
    }

    memcpy(plaintext, ciphertext, n);

    if (plainsize) {
        *plainsize = n;
    }

    return 0;
}
