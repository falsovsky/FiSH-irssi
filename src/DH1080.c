// New Diffie-Hellman 1080bit Key-exchange

/* For Diffie-Hellman key-exchange a 1080bit germain prime is used, the
   generator g=2 renders a field Fp from 1 to p-1. Therefore breaking it
   means to solve a discrete logarithm problem with no less than 1080bit.

   Base64 format is used to send the public keys over IRC.

   The calculated secret key is hashed with SHA-256, the result is converted
   to base64 for final use with blowfish. */

#include "DH1080.h"

// ### new sophie-germain 1080bit prime number ###
static char prime1080[135] = {
    0xFB, 0xE1, 0x02, 0x2E, 0x23, 0xD2, 0x13, 0xE8, 0xAC, 0xFA, 0x9A, 0xE8, 0xB9, 0xDF, 0xAD, 0xA3, 0xEA,
    0x6B, 0x7A, 0xC7, 0xA7, 0xB7, 0xE9, 0x5A, 0xB5, 0xEB, 0x2D, 0xF8, 0x58, 0x92, 0x1F, 0xEA, 0xDE, 0x95,
    0xE6, 0xAC, 0x7B, 0xE7, 0xDE, 0x6A, 0xDB, 0xAB, 0x8A, 0x78, 0x3E, 0x7A, 0xF7, 0xA7, 0xFA, 0x6A, 0x2B,
    0x7B, 0xEB, 0x1E, 0x72, 0xEA, 0xE2, 0xB7, 0x2F, 0x9F, 0xA2, 0xBF, 0xB2, 0xA2, 0xEF, 0xBE, 0xFA, 0xC8,
    0x68, 0xBA, 0xDB, 0x3E, 0x82, 0x8F, 0xA8, 0xBA, 0xDF, 0xAD, 0xA3, 0xE4, 0xCC, 0x1B, 0xE7, 0xE8, 0xAF,
    0xE8, 0x5E, 0x96, 0x98, 0xA7, 0x83, 0xEB, 0x68, 0xFA, 0x07, 0xA7, 0x7A, 0xB6, 0xAD, 0x7B, 0xEB, 0x61,
    0x8A, 0xCF, 0x9C, 0xA2, 0x89, 0x7E, 0xB2, 0x8A, 0x61, 0x89, 0xEF, 0xA0, 0x7A, 0xB9, 0x9A, 0x8A, 0x7F,
    0xA9, 0xAE, 0x29, 0x9E, 0xFA, 0x7B, 0xA6, 0x6D, 0xEA, 0xFE, 0xFB, 0xEF, 0xBF, 0x0B, 0x7D, 0x8B
};

// base16: FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B
// base10: 12745216229761186769575009943944198619149164746831579719941140425076456621824834322853258804883232842877311723249782818608677050956745409379781245497526069657222703636504651898833151008222772087491045206203033063108075098874712912417029101508315117935752962862335062591404043092163187352352197487303798807791605274487594646923

mpz_t b_prime1080;
randctx csprng;

BOOL DH1080_Init(void)
{
    unsigned char raw_buf[256];
    unsigned char iniHash[33] = { '\0' };
    FILE *hRnd;

    hRnd = fopen("/dev/urandom", "rb");     // don't use /dev/random, it's a blocking device
    if (!hRnd) return FALSE;

    // #*#*#*#*#* RNG START #*#*#*#*#*
    if (fread(raw_buf, 1, sizeof(raw_buf), hRnd) < 128) { /* At least 128 bytes of seeding */
        ZeroMemory(raw_buf, sizeof(raw_buf));
        fclose(hRnd);
        return FALSE;
    }
    fclose(hRnd);

    sha_file(iniPath, (char *)iniHash);
    memXOR((char *)raw_buf+128, (char *)iniHash, 32);
    sha_file((char *)get_irssi_config(), (char *)iniHash);
    memXOR((char *)raw_buf+128, (char *)iniHash, 32);
    ZeroMemory(iniHash, sizeof(iniHash));
    // first 128 byte in raw_buf: output from /dev/urandom
    // last 32 byte in raw_buf: SHA-256 digest from blow.ini and irssi.conf

    /* Seed and initialize ISAAC */
    memcpy(csprng.randrsl, raw_buf, sizeof(raw_buf));
    randinit(&csprng, TRUE);

    /* RNG END */

    initb64();

    mpz_init(b_prime1080);

    mpz_import(b_prime1080, DH1080_PRIME_BYTES, 1, 1, 0, 0, prime1080);

    return TRUE;
}

void DH1080_DeInit(void)
{
    mpz_clear(b_prime1080);
    memset(&csprng, 0, sizeof(csprng));
}


// verify the Diffie-Hellman public key as described in RFC 2631
BOOL DH_verifyPubKey(mpz_t b_pubkey)
{
    BOOL bRet = FALSE;

    // Verify that pubkey lies within the interval [2,p-1].
    // If it does not, the key is invalid.
    if ( (mpz_cmp(b_pubkey, b_prime1080) == -1) &&
            (mpz_cmp_ui(b_pubkey, 1) == 1) )
        bRet = TRUE;

    return bRet;
}

// Input:  priv_key = buffer of 200 bytes
//         pub_key  = buffer of 200 bytes
// Output: priv_key = Your private key
//         pub_key  = Your public key
int DH1080_gen(char *priv_key, char *pub_key)
{
    unsigned char raw_buf[256]; //, iniHash[33];
    //unsigned long seed;
    int iRet, i;
    size_t len;

    mpz_t b_privkey, b_pubkey, b_base;
    unsigned char temp[DH1080_PRIME_BYTES];
    //FILE *hRnd;

    priv_key[0]='0';
    priv_key[1]='\0';
    pub_key[0]='0';
    pub_key[1]='\0';

    mpz_init(b_privkey);
    mpz_init(b_pubkey);
    mpz_init_set_ui(b_base, 2);

    do {
        for (i=0; i < DH1080_PRIME_BYTES; i++)
            temp[i] = (unsigned char)rand(&csprng);
        mpz_import(b_privkey, DH1080_PRIME_BYTES, 1, 1, 0, 0, temp);
        mpz_mod(b_privkey, b_privkey, b_prime1080); /* [2, prime1080-1] */
    } while ( mpz_cmp_ui(b_privkey, 1) != 1); /* while smaller than 2 */

    mpz_powm(b_pubkey, b_base, b_privkey, b_prime1080);

    if (DH_verifyPubKey(b_pubkey)) {
        mpz_export(raw_buf, &len, 1, 1, 0, 0, b_privkey);
        mpz_clear(b_privkey);
        htob64((char *)raw_buf, priv_key, len);

        mpz_export(raw_buf, &len, 1, 1, 0, 0, b_pubkey);
        htob64((char *)raw_buf, pub_key, len);

        iRet=1;
    } else iRet=0;

    ZeroMemory(raw_buf, sizeof(raw_buf));

    mpz_clear(b_pubkey);
    mpz_clear(b_base);

    return iRet;
}

// Input:  MyPrivKey = Your private key
//         HisPubKey = Someones public key
// Output: MyPrivKey has been destroyed for security reasons
//         HisPubKey = the secret key
int DH1080_comp(char *MyPrivKey, char *HisPubKey)
{
    //int i=0;
    int iRet;
    unsigned char SHA256digest[35] = { '\0' };
    unsigned char base64_tmp[160];
    mpz_t b_myPrivkey, b_HisPubkey, b_theKey;
    size_t len;

    // Verify base64 strings
    if ((strspn(MyPrivKey, B64ABC) != strlen(MyPrivKey)) || (strspn(HisPubKey, B64ABC) != strlen(HisPubKey))) {
        memset(MyPrivKey, 0x20, strlen(MyPrivKey));
        memset(HisPubKey, 0x20, strlen(HisPubKey));
        return 0;
    }

    mpz_init(b_HisPubkey);
    mpz_init(b_theKey);

    len=b64toh(HisPubKey, (char *)base64_tmp);
    mpz_import(b_HisPubkey, len, 1, 1, 0, 0, base64_tmp);

    if (DH_verifyPubKey(b_HisPubkey)) {
        mpz_init(b_myPrivkey);

        len=b64toh(MyPrivKey, (char *)base64_tmp);
        mpz_import(b_myPrivkey, len, 1, 1, 0, 0, base64_tmp);
        memset(MyPrivKey, 0x20, strlen(MyPrivKey));

        mpz_powm(b_theKey, b_HisPubkey, b_myPrivkey, b_prime1080);
        mpz_clear(b_myPrivkey);

        mpz_export(base64_tmp, &len, 1, 1, 0, 0, b_theKey);
        SHA256_memory((char *)base64_tmp, len, (char *)SHA256digest);
        htob64((char *)SHA256digest, HisPubKey, 32);

        iRet=1;
    } else iRet=0;


    ZeroMemory(base64_tmp, sizeof(base64_tmp));
    ZeroMemory(SHA256digest, sizeof(SHA256digest));

    mpz_clear(b_theKey);
    mpz_clear(b_HisPubkey);

    return iRet;
}
