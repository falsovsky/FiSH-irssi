#include "blowfish.h"
#include <openssl/err.h>

const char B64[] =
"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


/* decode base64 string */
    static uint32_t
base64dec (char c)
{
    size_t i;

    for (i = 0; i < 64; i++)
        if (B64[i] == c)
            return i;

    return 0;
}

    static uint32_t
load32_be (const void *p)
{
    const unsigned char *in = p;
    return (uint32_t) in[0] << 24 |
        (uint32_t) in[1] << 16 | (uint32_t) in[2] << 8 | (uint32_t) in[3] << 0;
}

    static void
store32_be (void *p, uint32_t v)
{
    unsigned char *out = p;
    out[0] = v >> 24;
    out[1] = v >> 16;
    out[2] = v >> 8;
    out[3] = v >> 0;
}

    static int
bf_ecb_crypt (const unsigned char *key, int keylen,
              const unsigned char *in, unsigned char *out, int enc)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0, tmplen = 0;

    ctx = EVP_CIPHER_CTX_new ();
    if (!ctx)
        return 0;

    if (!EVP_CipherInit_ex (ctx, EVP_bf_ecb (), NULL, NULL, NULL, enc))
        goto fail;
    EVP_CIPHER_CTX_set_padding (ctx, 0);
    if (!EVP_CIPHER_CTX_set_key_length (ctx, keylen))
        goto fail;
    if (!EVP_CipherInit_ex (ctx, NULL, NULL, key, NULL, -1))
        goto fail;
    if (!EVP_CipherUpdate (ctx, out, &outlen, in, 8))
        goto fail;
    if (!EVP_CipherFinal_ex (ctx, out + outlen, &tmplen))
        goto fail;

    EVP_CIPHER_CTX_free (ctx);
    return 1;

fail:
    EVP_CIPHER_CTX_free (ctx);
    return 0;
}

    int
encrypt_string (const char *key, const char *str, char *dest, int len)
{
    int keylen;

    if (!key || !key[0])
        return 0;

    keylen = (int) strlen (key);

    while (len > 0)
    {
        const int blocksize = len < 8 ? len : 8;
        unsigned char block[8] = { 0 };
        unsigned char out[8];
        uint32_t v;
        size_t i;

        memcpy (block, str, blocksize);
        if (!bf_ecb_crypt ((const unsigned char *) key, keylen,
                           block, out, 1))
            return 0;

        for (v = load32_be (out + 4), i = 0; i < 6; ++i)
        {
            *dest++ = B64[v & 0x3f];
            v >>= 6;
        }

        for (v = load32_be (out + 0), i = 0; i < 6; ++i)
        {
            *dest++ = B64[v & 0x3f];
            v >>= 6;
        }

        len -= blocksize;
        str += blocksize;
    }

    *dest++ = 0;
    return 1;
}

    int
decrypt_string (const char *key, const char *str, char *dest, int len)
{
    uint32_t v;
    size_t i;
    int keylen;

    if (!key || !key[0])
        return 0;

    if (len % (8 * 6 / 4) != 0)
        return 0;

    keylen = (int) strlen (key);

    while (len > 0)
    {
        unsigned char block[8] = { 0 };
        unsigned char out[8];

        for (i = v = 0; i < 6; ++i)
            v |= base64dec (*str++) << (i * 6);
        store32_be (block + 4, v);

        for (i = v = 0; i < 6; ++i)
            v |= base64dec (*str++) << (i * 6);
        store32_be (block + 0, v);

        if (!bf_ecb_crypt ((const unsigned char *) key, keylen,
                           block, out, 0))
            return 0;

        memcpy (dest, out, 8);
        dest += 8;
        len -= 8 * 6 / 4;
    }

    *dest++ = 0;
    return 1;
}

    void
encrypt_key (const char *key, char *encryptedKey)
{
    static const char prefix[] = "+OK ";
    strcpy (encryptedKey, prefix);
    encrypt_string (iniKey, key, encryptedKey + strlen (prefix), strlen (key));
}