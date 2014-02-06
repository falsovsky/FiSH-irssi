// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#ifndef FISH2_NOOP_H_
#define FISH2_NOOP_H_

#include <stdio.h>

// Yeah, you should free the result.
int fish2_noop_encrypt (
    const char* key,
    const char* plaintext,
    size_t n,
    char** ciphertext,
    size_t* ciphersize);

int fish2_noop_decrypt (
    const char* key,
    const char* ciphertext,
    size_t n,
    char** plaintext,
    size_t* plainsize);

#endif // FISH2_NOOP_H_
