#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/blowfish.h>
#include "blowfish.h"

static const char B64[]="./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* decode base64 string */
static uint32_t base64dec(char c)
{
	size_t i;

    for (i = 0; i < 64; i++)
        if (B64[i] == c) return i;

    return 0;
}

int valid_blowfish(const char *str, int len)
{
    return strspn(str, B64) == (size_t)len;
}

static uint32_t load32_be(const void *p) {
	const unsigned char *in = p;
	return (uint32_t)in[0] << 24 |
	       (uint32_t)in[1] << 16 |
	       (uint32_t)in[2] <<  8 | 
	       (uint32_t)in[3] <<  0;
}

static void store32_be(void *p, uint32_t v) {
	unsigned char *out = p;
	out[0] = v >> 24;
	out[1] = v >> 16;
	out[2] = v >>  8;
	out[3] = v >>  0;
}

/* Returned string must be freed when done with it! */
int encrypt_string(const char *key, const char *str, char *dest, int len)
{
	BF_KEY bf_key;

	if ( !key || !key[0] )
		return 0;

	BF_set_key(&bf_key, strlen(key), (const unsigned char *)key);

	while( len > 0 ) {
		const size_t blocksize = len < 8 ? len : BF_BLOCK;
		unsigned char block[BF_BLOCK] = {0}; /* pad with zero */
		uint32_t v;
		size_t i;

		memcpy(block, str, blocksize);
		BF_ecb_encrypt(block, block, &bf_key, BF_ENCRYPT);

		for(v = load32_be(block + 4), i = 0; i < 6; ++i) {
			*dest++ = B64[v&0x3f];
			v >>= 6;
		}

		for(v = load32_be(block + 0), i = 0; i < 6; ++i) {
			*dest++ = B64[v&0x3f];
			v >>= 6;
		}

		len -= blocksize;
		str += blocksize;
	}

	*dest++ = 0;
	return 1;
}

int decrypt_string(const char *key, const char *str, char *dest, int len)
{
	BF_KEY bf_key;
	uint32_t v;
	size_t i;

	/* Pad encoded string with 0 bits in case it's bogus */
	if ( !key || !key[0] )
		return 0;

	/* length must be a multiple of BF_BLOCK encoded in base64 */
	if( len % (BF_BLOCK * 6 / 4) != 0 )
		return 0;
	
	BF_set_key(&bf_key, strlen(key), (const unsigned char *)key);
	while(len > 0) {
		unsigned char block[BF_BLOCK] = {0};
		
		for(i = v = 0; i < 6; ++i)
			v |= base64dec(*str++) << (i * 6);
		store32_be(block + 4, v);

		for(i = v = 0; i < 6; ++i)
			v |= base64dec(*str++) << (i * 6);
		store32_be(block + 0, v);

		BF_ecb_encrypt(block, block, &bf_key, BF_DECRYPT);

		memcpy(dest, block, BF_BLOCK);
		dest += BF_BLOCK;
		len -= BF_BLOCK * 6 / 4;
	}

	*dest++ = 0;
	return 1;
}

void encrypt_key(const char* master_key, const char *key, char *encryptedKey)
{
	static const char prefix[] = "+OK ";
	strcpy(encryptedKey, prefix);
	encrypt_string(iniKey, key, encryptedKey + strlen(prefix), strlen(key));
}
