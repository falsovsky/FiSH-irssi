
#include "key_store.h"
#include "inifile.h"
#include "blowfish.h"

#include <stdlib.h>
#include <string.h>

#define KEYBUF_SIZE (150)

struct key_store_s {
  char *filepath;
  char *filekey;
};

int key_store_init (
    key_store_t *ctx,
    const char* filepath,
    const char* filekey)
{
    (*ctx) = (key_store_t)malloc(sizeof(struct key_store_s));
    if (*ctx == NULL) {
        return -1;
    }

    (*ctx)->filepath = strdup(filepath);
    (*ctx)->filekey  = strdup(filekey);

    return 0;
}

void key_store_deinit (key_store_t ctx)
{
    free(ctx->filepath);
    free(ctx->filekey);
    free(ctx);
}

/* Load a base64 blowfish key for contact
 * If theKey is NULL, only a test is made (= IsKeySetForContact)
 * @param contactPtr
 * @param theKey
 * @return 1 if everything ok 0 if not
 */
int key_store_get (key_store_t ctx, const char* contact, char* key)
{
    char encrypted_key[KEYBUF_SIZE] = { '\0' };

    getIniValue(contact, "key", "", encrypted_key, KEYBUF_SIZE, ctx->filepath);

    // don't process, encrypted key not found in ini
    if (strlen(encrypted_key) < 16) return -1;

    // encrypted key not found
    if (strncmp(encrypted_key, "+OK ", 4) != 0) return -2;

    if (key) {
        // if it's not just a test, lets decrypt the key
        decrypt_string(ctx->filekey, encrypted_key + 4, key, strlen(encrypted_key + 4));
    }

    memset(encrypted_key, 0, sizeof(encrypted_key));
    return 0;
}

int key_store_set (key_store_t ctx, const char* contact, const char* key)
{
    char encrypted_key[KEYBUF_SIZE] = { '\0' };

    encrypt_key(key, encrypted_key);

    int ret = setIniValue(contact, "key", encrypted_key, ctx->filepath);

    memset(encrypted_key, 0, sizeof(encrypted_key));

    return ret == 1 ? 0 : ret; // hack while setIniValue doesn't return 0
}

int key_store_unset (key_store_t ctx, const char* contact)
{
    deleteIniValue(contact, "key", ctx->filepath);

    return 0; // TODO(hpeixoto): deleteIniValue should probably return something.
}

