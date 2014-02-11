// Copyright 2014 Hugo Peixoto

#include "blowfish.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/blowfish.h>

static const char b64table[] = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static int b64only (const char* str)
{
    return strspn(str, b64table) == strlen(str) ? 1 : 0;
}

static char b64encode (char c)
{
    return b64table[(int)c];
}

static char b64decode (char c)
{
    size_t i;
    size_t n = strlen(b64table);

    for (i = 0; i < n; ++i) {
        if (b64table[i] == c) {
            return i;
        }
    }

    return 0;
}

int openssl_blowfish_decrypt_string (
    const char* text_key,
    const char* data,
    char* dest,
    int n)
{
    BF_KEY bf_key;

    size_t in_size = strlen(data) / 12 * 12; // discard extra bytes.
    size_t i, j;

    memset(dest, 0, n);
    if (!b64only(data)) {
        return 0;
    }

    BF_set_key(&bf_key, strlen(text_key), (const unsigned char*)text_key);

    for (i = 0; i*12 < in_size; ++i) {
        uint32_t x[2] = { 0, 0 };
        unsigned char raw_encrypted[8] = { 0 };
        unsigned char raw_decrypted[8] = { 0 };

        for (j = 0; j < 12; ++j) {
            x[j/6] |= b64decode(data[i*12 + j]) << ((j%6) * 6);
        }

        for (j = 0; j < 8; ++j) {
            // Little endian, so everything gets reversed
            raw_encrypted[j] = 0xFF & (x[1-j/4] >> ((3-(j%4))*8));
        }

        BF_ecb_encrypt(raw_encrypted, raw_decrypted, &bf_key, BF_DECRYPT);

        // We must leave room for the final null terminator.
        for (j = 0; j < 8 && i*8+j < (size_t)n-1; ++j) {
            dest[i*8+j] = raw_decrypted[j];
        }
    }

    return 1;
}

int openssl_blowfish_encrypt_string (
    const char* text_key,
    const char* data,
    char* dest,
    int n)
{
    BF_KEY bf_key;

    size_t in_size = (strlen(data) + 7) / 8 * 8; // pad with zeros
    size_t i, j;

    memset(dest, 0, n);

    BF_set_key(&bf_key, strlen(text_key), (const unsigned char*)text_key);

    for (i = 0; i*8 < in_size; ++i) {
        uint32_t x[2] = { 0, 0 };
        unsigned char raw_decrypted[8] = { 0 };
        unsigned char raw_encrypted[8] = { 0 };

        for (j = 0; j < 8 && i*8+j < in_size; ++j) {
            raw_decrypted[j] = data[i*8+j];
        }

        BF_ecb_encrypt(raw_decrypted, raw_encrypted, &bf_key, BF_ENCRYPT);

        for (j = 0; j < 8; ++j) {
            // Little endian, so everything gets reversed
            x[1-j/4] |= raw_encrypted[j] << ((3-(j%4))*8);
        }

        // We must leave room for the final null terminator.
        for (j = 0; j < 12 && i*12+j < (size_t)n-1; ++j) {
            dest[i*12+j] = b64encode(0x3F & (x[j/6] >> ((j%6) * 6)));
        }
    }

    return 1;
}
