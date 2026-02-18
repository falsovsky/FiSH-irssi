#include "blowfish_cbc.h"

/*
 * Encrypt or decrypt a single BF_BLOCK (8 bytes) using Blowfish-CBC via EVP.
 * The ivec is updated in-place after each call, just like BF_cbc_encrypt did.
 */
    static int
bf_cbc_crypt (const unsigned char *key, int keylen,
              const unsigned char *in, unsigned char *out,
              unsigned char *ivec, int enc)
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0, tmplen = 0;

    ctx = EVP_CIPHER_CTX_new ();
    if (!ctx)
        return 0;

    if (!EVP_CipherInit_ex (ctx, EVP_bf_cbc (), NULL, NULL, NULL, enc))
        goto fail;
    EVP_CIPHER_CTX_set_padding (ctx, 0);
    if (!EVP_CIPHER_CTX_set_key_length (ctx, keylen))
        goto fail;
    if (!EVP_CipherInit_ex (ctx, NULL, NULL, key, ivec, -1))
        goto fail;
    if (!EVP_CipherUpdate (ctx, out, &outlen, in, BF_BLOCK))
        goto fail;
    if (!EVP_CipherFinal_ex (ctx, out + outlen, &tmplen))
        goto fail;

    /*
     * Update ivec manually, mimicking BF_cbc_encrypt behaviour:
     * - after encrypt: ivec = ciphertext block
     * - after decrypt: ivec = ciphertext block (i.e. the input)
     */
    if (enc)
        memcpy (ivec, out, BF_BLOCK);
    else
        memcpy (ivec, in, BF_BLOCK);

    EVP_CIPHER_CTX_free (ctx);
    return 1;

fail:
    EVP_CIPHER_CTX_free (ctx);
    return 0;
}

    int
encrypt_string_cbc (const char *key, const char *str, char *dest, int len)
{
    int keylen;
    unsigned char ivec[BF_BLOCK] = {0};
    BIO *l_mem = NULL, *l_b64 = NULL;
    int ret = -1;

    if (!key || !key[0])
        return 0;

    keylen = (int) strlen (key);

    l_b64 = BIO_new (BIO_f_base64 ());
    if (!l_b64)
        goto fail;
    BIO_set_flags (l_b64, BIO_FLAGS_BASE64_NO_NL);
    l_mem = BIO_new (BIO_s_mem ());
    if (!l_mem)
        goto fail;
    l_b64 = BIO_push (l_b64, l_mem);

    {
        /* for some f*cked up reason, Mircryption's CBC blowfish does not use an
           explicit IV, but prepends 8 bytes of random data to the actual string
           instead, so we have to do this too... */
        unsigned char block[BF_BLOCK] = {0};
        unsigned char out[BF_BLOCK];
        RAND_bytes (block, sizeof (block));
        if (!bf_cbc_crypt ((const unsigned char *) key, keylen,
                           block, out, ivec, 1))
            goto fail;
        if (BIO_write (l_b64, out, sizeof (out)) != sizeof (out))
            goto fail;
    }

    while (len > 0)
    {
        const int blocksize = len < BF_BLOCK ? len : BF_BLOCK;
        unsigned char block[BF_BLOCK] = { 0 }; /* pad with zero */
        unsigned char out[BF_BLOCK];

        memcpy (block, str, blocksize);
        if (!bf_cbc_crypt ((const unsigned char *) key, keylen,
                           block, out, ivec, 1))
            goto fail;

        if (BIO_write (l_b64, out, sizeof (out)) != sizeof (out))
            goto fail;

        len -= blocksize;
        str += blocksize;
    }

    {
        BUF_MEM *l_ptr = NULL;
        BIO_flush (l_b64);
        BIO_get_mem_ptr (l_b64, &l_ptr);
        memcpy (dest, l_ptr->data, l_ptr->length);
        dest[l_ptr->length] = 0;
        ret = 1;
    }

fail:
    if (l_b64)
        BIO_free_all (l_b64);
    return ret;
}

    int
decrypt_string_cbc (const char *key, const char *str, char *dest, int len)
{
    int keylen;
    BIO *l_b64 = NULL, *l_mem = NULL;
    int ret = -1;
    unsigned char ivec[BF_BLOCK] = {0};
    unsigned char block[BF_BLOCK] = {0};
    unsigned char out[BF_BLOCK];
    char *dest_begin = dest;
    int inlen = 0;

    if (!key || !key[0])
        return 0;

    keylen = (int) strlen (key);

    l_b64 = BIO_new (BIO_f_base64 ());
    if (!l_b64)
        goto fail;
    BIO_set_flags (l_b64, BIO_FLAGS_BASE64_NO_NL);
    l_mem = BIO_new_mem_buf ((char *) str, len);
    if (!l_mem)
        goto fail;
    l_b64 = BIO_push (l_b64, l_mem);

    while ((inlen = BIO_read (l_b64, block, sizeof (block))) > 0)
    {
        if (inlen != BF_BLOCK)
        {
            ret *= -1;
            break;
        }

        if (!bf_cbc_crypt ((const unsigned char *) key, keylen,
                           block, out, ivec, 0))
            goto fail;

        memcpy (dest, out, BF_BLOCK);
        dest += BF_BLOCK;
    }
    *dest++ = 0;
    /* get rid of first 8 bytes (the random prefix) */
    memmove (dest_begin, dest_begin + BF_BLOCK, strlen (dest_begin + BF_BLOCK) + 1);
    ret *= -1;

fail:
    if (l_b64)
        BIO_free_all (l_b64);
    return ret;
}