#include "blowfish.h"

#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#define IP_SIZE 1024
#define OP_SIZE 1024 + EVP_MAX_BLOCK_LENGTH

const unsigned char B64[]="./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


int encrypt_string(const char *key, const char *str, char *dest, int len)
{
    EVP_CIPHER_CTX ctx;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit(&ctx, EVP_bf_ecb(), (const unsigned char *)key, NULL);

    EVP_EncryptUpdate(&ctx, (unsigned char *)dest, &len, (const unsigned char *)str, (int)NULL);
    EVP_EncryptFinal(&ctx, (unsigned char *)dest, NULL);

    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;
}

int decrypt_string(const char *key, const char *str, char *dest, int len)
{
    EVP_CIPHER_CTX ctx;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit(&ctx, EVP_bf_ecb(), (const unsigned char *)key, NULL);

    EVP_DecryptUpdate(&ctx, (unsigned char *)dest, &len, (const unsigned char *)str, (int)NULL);
    EVP_DecryptFinal(&ctx, (unsigned char *)dest, NULL);

    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;
}

void encrypt_key(const char *key, char *encryptedKey)
{
    int i;
    strcpy(encryptedKey, "+OK ");
    i=strlen(key);
    encrypt_string(iniKey, key, encryptedKey+4, i>80 ? 80 : i);
}
