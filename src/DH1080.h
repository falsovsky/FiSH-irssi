#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <gmp.h>

#include "SHA256.h"
#include "rand.h"

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


BOOL DH1080_Init(const char* ini_path, const char* conf_path);
void DH1080_DeInit();

#define DH1080_PRIME_BITS	1080
#define DH1080_PRIME_BYTES	135
#define ZeroMemory(dest,count) memset((void *)dest, 0, count)

void memXOR(char *s1, const char *s2, int n);
