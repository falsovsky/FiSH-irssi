#include "blowfish.h"

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

/* Returned string must be freed when done with it! */
    int
encrypt_string (const char *key, const char *str, char *dest, int len)
{
    BF_KEY bf_key;

    if (!key || !key[0])
        return 0;

    BF_set_key (&bf_key, strlen (key), (const unsigned char *) key);

    while (len > 0)
    {
        const size_t blocksize = len < 8 ? len : BF_BLOCK;
        unsigned char block[BF_BLOCK] = { 0 }; /* pad with zero */
        uint32_t v;
        size_t i;

        memcpy (block, str, blocksize);
        BF_ecb_encrypt (block, block, &bf_key, BF_ENCRYPT);

        for (v = load32_be (block + 4), i = 0; i < 6; ++i)
        {
            *dest++ = B64[v & 0x3f];
            v >>= 6;
        }

        for (v = load32_be (block + 0), i = 0; i < 6; ++i)
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
encrypt_string_cbc (const char *key, const char *str, char *dest, int len)
{
    BF_KEY bf_key;
    char ivec[8] = {0};
    //unsigned char data[500];
    //unsigned int data_ptr = 0;

    if (!key || !key[0])
        return 0;

    BF_set_key (&bf_key, strlen (key), (const unsigned char *) key);

    while (len > 0)
    {
        const size_t blocksize = len < 8 ? len : BF_BLOCK;
        unsigned char block[BF_BLOCK] = { 0 }; /* pad with zero */
        uint32_t v;
        size_t i;

        memcpy (block, str, blocksize);
        //BF_ecb_encrypt(block, block, &bf_key, BF_ENCRYPT);
        BF_cbc_encrypt(block, block, blocksize, &bf_key, ivec, BF_ENCRYPT);

        for (v = load32_be (block + 4), i = 0; i < 6; ++i)
        {
            *dest++ = B64[v & 0x3f];
            v >>= 6;
        }

        for (v = load32_be (block + 0), i = 0; i < 6; ++i)
        {
            *dest++ = B64[v & 0x3f];
            v >>= 6;
        }

        /* Pensei fazer isto aqui e depois o b64_op em baixo. Mas crasha */
        //memcpy(data + data_ptr, block, BF_BLOCK);
        //data_ptr += BF_BLOCK;

        len -= blocksize;
        str += blocksize;
    }

    //b64_op(data, sizeof(data), dest, sizeof(dest), 0);
    *dest++ = 0;
    return 1;
}

    int
decrypt_string (const char *key, const char *str, char *dest, int len)
{
    BF_KEY bf_key;
    uint32_t v;
    size_t i;

    /* Pad encoded string with 0 bits in case it's bogus */
    if (!key || !key[0])
        return 0;

    /* length must be a multiple of BF_BLOCK encoded in base64 */
    if (len % (BF_BLOCK * 6 / 4) != 0)
        return 0;

    BF_set_key (&bf_key, strlen (key), (const unsigned char *) key);
    while (len > 0)
    {
        unsigned char block[BF_BLOCK] = { 0 };

        for (i = v = 0; i < 6; ++i)
            v |= base64dec (*str++) << (i * 6);
        store32_be (block + 4, v);

        for (i = v = 0; i < 6; ++i)
            v |= base64dec (*str++) << (i * 6);
        store32_be (block + 0, v);

        BF_ecb_encrypt (block, block, &bf_key, BF_DECRYPT);

        memcpy (dest, block, BF_BLOCK);
        dest += BF_BLOCK;
        len -= BF_BLOCK * 6 / 4;
    }

    *dest++ = 0;
    return 1;
}

    int
decrypt_string_cbc (const char *key, const char *str, char *dest, int len)
{
    BF_KEY bf_key;
    uint32_t v;
    size_t i;
    char ivec[8] = {0};

    /* Pad encoded string with 0 bits in case it's bogus */
    if (!key || !key[0])
        return 0;

    /* length must be a multiple of BF_BLOCK encoded in base64 */
    if (len % (BF_BLOCK * 6 / 4) != 0)
        return 0;

    BF_set_key (&bf_key, strlen (key), (const unsigned char *) key);
    while (len > 0)
    {
        unsigned char block[BF_BLOCK] = { 0 };

        for (i = v = 0; i < 6; ++i)
            v |= base64dec (*str++) << (i * 6);
        store32_be (block + 4, v);

        for (i = v = 0; i < 6; ++i)
            v |= base64dec (*str++) << (i * 6);
        store32_be (block + 0, v);

        //BF_ecb_encrypt (block, block, &bf_key, BF_DECRYPT);
        BF_cbc_encrypt(block, block, BF_BLOCK, &bf_key, ivec, BF_DECRYPT);

        memcpy (dest, block, BF_BLOCK);
        dest += BF_BLOCK;
        len -= BF_BLOCK * 6 / 4;
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

int b64_op(const unsigned char* in, int in_len,
              char *out, int out_len, int op)
{
    int ret = 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);
    if (op == 0)
    {
        ret = BIO_write(b64, in, in_len);
        BIO_flush(b64);
        if (ret > 0)
        {
            ret = BIO_read(bio, out, out_len);
        }

    } else
    {
        ret = BIO_write(bio, in, in_len);
        BIO_flush(bio);
        if (ret)
        {
            ret = BIO_read(b64, out, out_len);
        }
    }
    BIO_free(b64); // MEMORY LEAK HERE?
    return ret;
}
