// New Diffie-Hellman 1080bit Key-exchange

/* For Diffie-Hellman key-exchange a 1080bit germain prime is used, the
   generator g=2 renders a field Fp from 1 to p-1. Therefore breaking it
   means to solve a discrete logarithm problem with no less than 1080bit.

   Base64 format is used to send the public keys over IRC.

   The calculated secret key is hashed with SHA-256, the result is converted
   to base64 for final use with blowfish. */

#include "DH1080.h"

// ### new sophie-germain 1080bit prime number ###
static const unsigned char prime1080[DH1080_PRIME_BYTES] =
{
    0xFB, 0xE1, 0x02, 0x2E, 0x23, 0xD2, 0x13, 0xE8, 0xAC, 0xFA, 0x9A, 0xE8,
    0xB9, 0xDF, 0xAD, 0xA3, 0xEA,
    0x6B, 0x7A, 0xC7, 0xA7, 0xB7, 0xE9, 0x5A, 0xB5, 0xEB, 0x2D, 0xF8, 0x58,
    0x92, 0x1F, 0xEA, 0xDE, 0x95,
    0xE6, 0xAC, 0x7B, 0xE7, 0xDE, 0x6A, 0xDB, 0xAB, 0x8A, 0x78, 0x3E, 0x7A,
    0xF7, 0xA7, 0xFA, 0x6A, 0x2B,
    0x7B, 0xEB, 0x1E, 0x72, 0xEA, 0xE2, 0xB7, 0x2F, 0x9F, 0xA2, 0xBF, 0xB2,
    0xA2, 0xEF, 0xBE, 0xFA, 0xC8,
    0x68, 0xBA, 0xDB, 0x3E, 0x82, 0x8F, 0xA8, 0xBA, 0xDF, 0xAD, 0xA3, 0xE4,
    0xCC, 0x1B, 0xE7, 0xE8, 0xAF,
    0xE8, 0x5E, 0x96, 0x98, 0xA7, 0x83, 0xEB, 0x68, 0xFA, 0x07, 0xA7, 0x7A,
    0xB6, 0xAD, 0x7B, 0xEB, 0x61,
    0x8A, 0xCF, 0x9C, 0xA2, 0x89, 0x7E, 0xB2, 0x8A, 0x61, 0x89, 0xEF, 0xA0,
    0x7A, 0xB9, 0x9A, 0x8A, 0x7F,
    0xA9, 0xAE, 0x29, 0x9E, 0xFA, 0x7B, 0xA6, 0x6D, 0xEA, 0xFE, 0xFB, 0xEF,
    0xBF, 0x0B, 0x7D, 0x8B
};

/*
 * Global EVP_PKEY holding just the DH parameters (p and g).
 * Used as a template to generate per-session keypairs.
 */
static EVP_PKEY *g_dh_params = NULL;

int DH1080_Init(void)
{
    BIGNUM *p = NULL, *g = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    initb64();

    p = BN_bin2bn(prime1080, DH1080_PRIME_BYTES, NULL);
    g = BN_new();
    if (!p || !g)
        goto fail;
    BN_set_word(g, 2);

    bld = OSSL_PARAM_BLD_new();
    if (!bld)
        goto fail;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
        goto fail;
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g))
        goto fail;

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params)
        goto fail;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);
    if (!ctx)
        goto fail;
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto fail;
    if (EVP_PKEY_fromdata(ctx, &g_dh_params, EVP_PKEY_KEY_PARAMETERS, params) <= 0)
        goto fail;

    ret = 1;

fail:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(g);
    return ret;
}

void DH1080_DeInit(void)
{
    EVP_PKEY_free(g_dh_params);
    g_dh_params = NULL;
}

/* Verify the DH public key: must satisfy 2 <= pk <= p-2 */
static int DH_verifyPubKey(const BIGNUM *pk)
{
    BIGNUM *p = NULL, *tmp = NULL;
    int ret = 0;

    if (!EVP_PKEY_get_bn_param(g_dh_params, OSSL_PKEY_PARAM_FFC_P, &p))
        goto done;
    tmp = BN_new();
    if (!tmp)
        goto done;

    BN_set_word(tmp, 2);
    if (BN_cmp(pk, tmp) < 0)   /* pk < 2 */
        goto done;

    BN_copy(tmp, p);
    BN_sub_word(tmp, 2);
    if (BN_cmp(pk, tmp) > 0)   /* pk > p-2 */
        goto done;

    ret = 1;
done:
    BN_free(p);
    BN_free(tmp);
    return ret;
}

// Input:  priv_key = buffer of 200 bytes
//         pub_key  = buffer of 200 bytes
// Output: priv_key = Your private key
//         pub_key  = Your public key
int DH1080_gen(char *priv_key, char *pub_key)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *keypair = NULL;
    BIGNUM *pub = NULL, *priv = NULL;
    unsigned char w[DH1080_PRIME_BYTES];
    int n, ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, g_dh_params, NULL);
    if (!ctx)
        goto fail;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto fail;
    if (EVP_PKEY_keygen(ctx, &keypair) <= 0)
        goto fail;

    if (!EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_PRIV_KEY, &priv))
        goto fail;
    if (!EVP_PKEY_get_bn_param(keypair, OSSL_PKEY_PARAM_PUB_KEY, &pub))
        goto fail;

    memset(w, 0, sizeof w);
    n = BN_bn2bin(priv, w);
    htob64((char *)w, priv_key, n);

    memset(w, 0, sizeof w);
    n = BN_bn2bin(pub, w);
    htob64((char *)w, pub_key, n);

    ret = 1;

fail:
    OPENSSL_cleanse(w, sizeof w);
    BN_free(pub);
    BN_clear_free(priv);
    EVP_PKEY_free(keypair);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Helper: build an EVP_PKEY for DHX from BIGNUMs.
 * selection = EVP_PKEY_PUBLIC_KEY or EVP_PKEY_KEYPAIR.
 */
static EVP_PKEY *build_dh_pkey(const BIGNUM *pub, const BIGNUM *priv,
                                int selection)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *p = NULL, *g = NULL;

    EVP_PKEY_get_bn_param(g_dh_params, OSSL_PKEY_PARAM_FFC_P, &p);
    EVP_PKEY_get_bn_param(g_dh_params, OSSL_PKEY_PARAM_FFC_G, &g);

    bld = OSSL_PARAM_BLD_new();
    if (!bld) goto fail;

    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, pub);
    if (priv)
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto fail;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);
    if (!ctx) goto fail;
    if (EVP_PKEY_fromdata_init(ctx) <= 0) goto fail;
    if (EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0)
        pkey = NULL;

fail:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(g);
    return pkey;
}

// Input:  MyPrivKey = Your private key
//         HisPubKey = Someones public key
// Output: MyPrivKey has been destroyed for security reasons
//         HisPubKey = the secret key
int DH1080_comp(char *MyPrivKey, char *HisPubKey)
{
    unsigned char base64_tmp[512] = {0};
    int result = 0;
    int len;
    BIGNUM *pk = NULL, *priv_bn = NULL, *pub_bn = NULL;
    EVP_PKEY *their_key = NULL, *my_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    BN_CTX *bnctx = NULL;

    // Verify base64 strings
    if ((strspn(MyPrivKey, B64ABC) != strlen(MyPrivKey))
            || (strspn(HisPubKey, B64ABC) != strlen(HisPubKey))) {
        memset(MyPrivKey, 0x20, strlen(MyPrivKey));
        memset(HisPubKey, 0x20, strlen(HisPubKey));
        return 0;
    }

    // Decode and verify their public key
    len = b64toh(HisPubKey, (char *)base64_tmp);
    pk = BN_bin2bn(base64_tmp, len, NULL);
    if (!pk || !DH_verifyPubKey(pk))
        goto fail;

    their_key = build_dh_pkey(pk, NULL, EVP_PKEY_PUBLIC_KEY);
    if (!their_key)
        goto fail;

    // Decode our private key and derive matching public key: pub = g^priv mod p
    len = b64toh(MyPrivKey, (char *)base64_tmp);
    priv_bn = BN_bin2bn(base64_tmp, len, NULL);
    memset(MyPrivKey, 0x20, strlen(MyPrivKey));
    if (!priv_bn)
        goto fail;

    {
        BIGNUM *p = NULL, *g = NULL;
        EVP_PKEY_get_bn_param(g_dh_params, OSSL_PKEY_PARAM_FFC_P, &p);
        EVP_PKEY_get_bn_param(g_dh_params, OSSL_PKEY_PARAM_FFC_G, &g);
        pub_bn = BN_new();
        bnctx = BN_CTX_new();
        BN_mod_exp(pub_bn, g, priv_bn, p, bnctx);
        BN_CTX_free(bnctx); bnctx = NULL;
        BN_free(p);
        BN_free(g);
    }

    my_key = build_dh_pkey(pub_bn, priv_bn, EVP_PKEY_KEYPAIR);
    if (!my_key)
        goto fail;

    // Derive shared secret, hash with SHA-256, encode to base64
    {
        unsigned char shared_key[DH1080_PRIME_BYTES] = {0};
        unsigned char sha256[32] = {0};
        size_t shared_len = sizeof(shared_key);

        derive_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, my_key, NULL);
        if (!derive_ctx) goto fail;
        if (EVP_PKEY_derive_init(derive_ctx) <= 0) goto fail;
        if (EVP_PKEY_derive_set_peer(derive_ctx, their_key) <= 0) goto fail;
        if (EVP_PKEY_derive(derive_ctx, shared_key, &shared_len) <= 0) goto fail;

        SHA256(shared_key, shared_len, sha256);
        htob64((char *)sha256, HisPubKey, 32);
        result = 1;

        OPENSSL_cleanse(shared_key, sizeof shared_key);
    }

fail:
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(their_key);
    EVP_PKEY_free(my_key);
    BN_free(pk);
    BN_clear_free(priv_bn);
    BN_free(pub_bn);
    OPENSSL_cleanse(base64_tmp, sizeof base64_tmp);
    return result;
}