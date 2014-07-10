
#include <string.h>
#include <openssl/sha.h>
#include "password.h"

void key_from_password(const char *a_password, char *a_key)
{
	unsigned char digest[256 / 8] = {0};	// SHA 256 uses 256/8 bytes.
	int i;

	SHA256((const unsigned char *)a_password, strlen(a_password), digest);
	for (i = 0; i < 40872; i++) {
		SHA256(digest, 32, digest);
	}

	memcpy(a_key, digest, sizeof(digest));
}

void key_hash(const char *a_key, char *a_hash)
{
	unsigned char digest[256 / 8];
	int i;

	memcpy(digest, a_key, sizeof(digest));
	for (i = 0; i < 30752; i++) {
		SHA256(digest, 32, digest);
	}

	memcpy(a_hash, digest, sizeof(digest));
}
