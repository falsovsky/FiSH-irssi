// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#include "fish2/blowcrypt.h"
#include "blowfish.h"

int fish2_blowfish_encrypt (
    const char* key,
    const char* plaintext,
    size_t n,
    char** ciphertext,
    size_t* ciphersize)
{
    size_t cipher_size = (n + 7) / 8 * 12 + 1;

    *ciphertext = (char*)malloc(cipher_size);

    if (*ciphertext == NULL) {
        return -1;
    }

    encrypt_string(key, plaintext, *ciphertext, n);
    if (ciphersize) {
        *ciphersize = cipher_size;
    }

    return 0;
}

int fish2_blowfish_decrypt (
    const char* key,
    const char* ciphertext,
    size_t n,
    char** plaintext,
    size_t* plainsize,
    int* broken)
{
    size_t plain_size = n / 12 * 8 + 1;

    if (n < 12 || !valid_blowfish(ciphertext, n)) {
        return -1;
    }

    *plaintext = (char*)malloc(plain_size);

    if (*plaintext == NULL) {
        return -2;
    }

    decrypt_string(key, ciphertext, *plaintext, plain_size);
    if (plainsize) {
        *plainsize = plain_size;
        *broken = n % 12;
    }

    return 0;
}
