
#ifndef DH_1080_H_
#define DH1080_H_

struct dh1080_s;
typedef struct dh1080_s* dh1080_t;

// Initializes diffie-hellman exchange structures.
int DH1080_Init(dh1080_t *ctx, const char seed[256]);

// Frees all allocated resources regarding the DH context.
void DH1080_DeInit(dh1080_t ctx);

// Input:  priv_key = buffer of 200 bytes
//         pub_key  = buffer of 200 bytes
// Output: priv_key = Your private key
//         pub_key  = Your public key
int DH1080_gen(dh1080_t ctx, char *priv_key, char *pub_key);

// Input:  MyPrivKey = Your private key
//         HisPubKey = Someones pubic key
// Output: MyPrivKey has been destroyed for security reasons
//         HisPubKey = the secret key
int DH1080_comp(dh1080_t ctx, char *MyPrivKey, char *HisPubKey);

#endif // DH_1080_H_

