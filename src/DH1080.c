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

// base16: FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B
// base10: 12745216229761186769575009943944198619149164746831579719941140425076456621824834322853258804883232842877311723249782818608677050956745409379781245497526069657222703636504651898833151008222772087491045206203033063108075098874712912417029101508315117935752962862335062591404043092163187352352197487303798807791605274487594646923

static DH * g_dh;

int DH1080_Init(void)
{
    initb64();
    g_dh = DH_new();
    if(g_dh) {
        int codes = 0;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3000000L)
        g_dh->p = BN_bin2bn(prime1080, DH1080_PRIME_BYTES, NULL);
        g_dh->g = BN_new(); BN_set_word(g_dh->g, 2);
        return DH_check(g_dh, &codes) && codes == 0;
#else
        BIGNUM *p;
        BIGNUM *g = BN_new();
        p = BN_bin2bn(prime1080, DH1080_PRIME_BYTES, NULL);
        BN_set_word(g, 2);
        DH_set0_pqg(g_dh, p, NULL, g);
        return DH_check(g_dh, &codes) && codes == 0;
#endif
    }
    return 0;
}

void DH1080_DeInit(void)
{
    DH_free(g_dh);
}

// verify the Diffie-Hellman public key as described in RFC 2631
int DH_verifyPubKey(BIGNUM * pk)
{
    int codes = 0;
    return DH_check_pub_key(g_dh, pk, &codes) && codes == 0;
}

// Input:  priv_key = buffer of 200 bytes
//         pub_key  = buffer of 200 bytes
// Output: priv_key = Your private key
//         pub_key  = Your public key
int DH1080_gen(char *priv_key, char *pub_key)
{
    unsigned char w[DH1080_PRIME_BYTES];
    int n;

    DH * dh = DHparams_dup(g_dh);

    DH_generate_key(dh);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3000000L)
    memset(w, 0, sizeof w);
    n = BN_bn2bin(dh->priv_key, w);
    htob64((char *)w, priv_key, n);

    memset(w, 0, sizeof w);
    n = BN_bn2bin(dh->pub_key, w);
    htob64((char *)w, pub_key, n);
#else
    const BIGNUM *pubkey, *privkey;
    DH_get0_key(dh, &pubkey, &privkey);

    memset(w, 0, sizeof w);
    n = BN_bn2bin(privkey, w);
    htob64((char *)w, priv_key, n);

    memset(w, 0, sizeof w);
    n = BN_bn2bin(pubkey, w);
    htob64((char *)w, pub_key, n);
#endif

    OPENSSL_cleanse(w, sizeof w);
    DH_free(dh);
    return 1;
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
    BIGNUM * pk = NULL;
    DH * dh = NULL;

    // Verify base64 strings
    if ((strspn(MyPrivKey, B64ABC) != strlen(MyPrivKey))
            || (strspn(HisPubKey, B64ABC) != strlen(HisPubKey))) {
        memset(MyPrivKey, 0x20, strlen(MyPrivKey));
        memset(HisPubKey, 0x20, strlen(HisPubKey));
        return 0;
    }

    dh = DHparams_dup(g_dh);

    len = b64toh(HisPubKey, (char *)base64_tmp);
    pk = BN_bin2bn(base64_tmp, len, NULL);

    if( DH_verifyPubKey(pk) ) {
        unsigned char shared_key[DH1080_PRIME_BYTES] = {0};
        unsigned char sha256[32] = {0};

        len = b64toh(MyPrivKey, (char *)base64_tmp);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3000000L)
        dh->priv_key = BN_bin2bn(base64_tmp, len, NULL);
#else
        BIGNUM *temp_pub_key = BN_new();
        BIGNUM *priv_key = BN_bin2bn(base64_tmp, len, NULL);
        DH_set0_key(dh, temp_pub_key, priv_key);
#endif
        memset(MyPrivKey, 0x20, strlen(MyPrivKey));

        len = DH_compute_key(shared_key, pk, dh);

        SHA256(shared_key, len, sha256);
        htob64((char *)sha256, HisPubKey, 32);
        result = 1;
    }

    BN_free(pk);
    DH_free(dh);
    OPENSSL_cleanse(base64_tmp, sizeof base64_tmp);
    return result;
}
