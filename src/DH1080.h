
#ifndef DH_1080_H_
#define DH1080_H_

// Input:  priv_key = buffer of 200 bytes
//         pub_key  = buffer of 200 bytes
// Output: priv_key = Your private key
//         pub_key  = Your public key
int DH1080_gen(char *priv_key, char *pub_key);

// Input:  MyPrivKey = Your private key
//         HisPubKey = Someones pubic key
// Output: MyPrivKey has been destroyed for security reasons
//         HisPubKey = the secret key
int DH1080_comp(char *MyPrivKey, char *HisPubKey);

// Initializes diffie-hellman exchange structures.
int DH1080_Init(const char seed[256]);

void DH1080_DeInit();

#endif // DH_1080_H_

