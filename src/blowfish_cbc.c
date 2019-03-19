#include "blowfish_cbc.h"

    int
encrypt_string_cbc (const char *key, const char *str, char *dest, int len)
{
    BF_KEY bf_key;
    unsigned char ivec[BF_BLOCK] = {0};
    BIO *l_mem = NULL, *l_b64 = NULL;
    int ret = -1;

    if (!key || !key[0])
        return 0;

    BF_set_key (&bf_key, strlen (key), (const unsigned char *) key);

    l_b64 = BIO_new(BIO_f_base64());
    if(!l_b64) {
        goto fail;
    }
    BIO_set_flags(l_b64, BIO_FLAGS_BASE64_NO_NL);
    l_mem = BIO_new(BIO_s_mem());
    if(!l_mem) {
        goto fail;
    }
    l_b64 = BIO_push(l_b64, l_mem);

    {
        /* for some f*cked up reason, Mircryption's CBC blowfish does not use an
           explicit IV, but prepends 8 bytes of random data to the actual string
           instead, so we have to do this too... */
        unsigned char block[BF_BLOCK] = {0};
        RAND_bytes(block, sizeof(block));
        BF_cbc_encrypt(block, block, BF_BLOCK, &bf_key, ivec, BF_ENCRYPT);
        if(BIO_write(l_b64, block, sizeof(block)) != sizeof(block)) {
            goto fail;
        }
    }

    while (len > 0)
    {
        const size_t blocksize = len < 8 ? len : BF_BLOCK;
        unsigned char block[BF_BLOCK] = { 0 }; /* pad with zero */

        memcpy (block, str, blocksize);
        BF_cbc_encrypt(block, block, BF_BLOCK, &bf_key, ivec, BF_ENCRYPT);

        if(BIO_write(l_b64, block, sizeof(block)) != sizeof(block)) {
            goto fail;
        }

        len -= blocksize;
        str += blocksize;
    }

    BUF_MEM *l_ptr = NULL;
    BIO_flush(l_b64);
    BIO_get_mem_ptr(l_b64, &l_ptr);
    memcpy(dest, l_ptr->data, l_ptr->length);
    dest[l_ptr->length] = 0;
    ret = 1;
fail:
    if(l_b64) {
        BIO_free_all(l_b64);
    }
    return ret;
}

    int
decrypt_string_cbc (const char *key, const char *str, char *dest, int len)
{
    BF_KEY bf_key;
    BIO *l_b64 = NULL;
    int ret = -1;
    unsigned char ivec[BF_BLOCK] = {0};
    unsigned char block[BF_BLOCK] = {0};
    char * dest_begin = dest;
    int inlen = 0;

    /* Pad encoded string with 0 bits in case it's bogus */
    if (!key || !key[0])
        return 0;

    BF_set_key (&bf_key, strlen (key), (const unsigned char *) key);

    l_b64 = BIO_new(BIO_f_base64());
    if(!l_b64) {
        goto fail;
    }
    BIO_set_flags(l_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *l_mem = BIO_new_mem_buf(str, len);
    if(!l_mem) {
        goto fail;
    }
    l_b64 = BIO_push(l_b64, l_mem);

    while ((inlen = BIO_read(l_b64, block, sizeof(block))) > 0)
    {
        if(inlen != BF_BLOCK) {
            ret *= -1;
            break;
        }

        BF_cbc_encrypt(block, block, BF_BLOCK, &bf_key, ivec, BF_DECRYPT);

        memcpy (dest, block, BF_BLOCK);
        dest += BF_BLOCK;
    }
    *dest++ = 0;
    // get rid of first 8 bytes
    memmove(dest_begin, dest_begin + BF_BLOCK, strlen(dest_begin + BF_BLOCK) + 1);
    ret *= -1;
fail:
    if(l_b64) {
        BIO_free_all(l_b64);
    }
    return ret;
}
