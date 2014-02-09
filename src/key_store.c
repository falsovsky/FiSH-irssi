// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#include "key_store.h"
#include "inifile.h"
#include "blowfish.h"
#include "password.h"
#include "base64.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define KEYBUF_SIZE (150)

static const char default_iniKey[] = "blowinikey";

static int recrypt_ini_file (const char*, const char*, const char*, const char*);
static void calculate_password_key_and_hash (const char*, char*, char*);

struct key_store_s {
  char *filepath;
  char *filekey;
};

int key_store_init (
    key_store_t *ctx,
    const char* filepath)
{
    (*ctx) = (key_store_t)malloc(sizeof(struct key_store_s));
    if (*ctx == NULL) {
        return -1;
    }

    (*ctx)->filepath = strdup(filepath);
    (*ctx)->filekey = NULL;

    return 0;
}

void key_store_deinit (key_store_t ctx)
{
    free(ctx->filepath);
    free(ctx->filekey);
    free(ctx);
}

int key_store_has_master_key (
    key_store_t ctx)
{
    char value[50] = { '\0' };

    getIniValue("FiSH", "ini_password_Hash", "", value, 50, ctx->filepath);

    return strncmp(value, "", 50) != 0;
}

int key_store_validate_master_key (
    key_store_t ctx,
    const char* password)
{
    char key[50];
    char hash[50];
    char current_hash[50] = { '\0' };

    calculate_password_key_and_hash(password, key, hash);

    getIniValue("FiSH", "ini_password_Hash", "", current_hash, 50, ctx->filepath);

    if (strncmp(password ? hash : "", current_hash, 50) != 0) {
        memset(key, 0, sizeof(key));
        memset(hash, 0, sizeof(hash));
        memset(current_hash, 0, sizeof(current_hash));
        return -1;
    }

    free(ctx->filekey);
    ctx->filekey = strdup(key);

    memset(key, 0, sizeof(key));
    memset(hash, 0, sizeof(hash));
    memset(current_hash, 0, sizeof(current_hash));
    return 0;
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
        decrypt_string(
            ctx->filekey,
            encrypted_key + 4,
            key,
            KEYBUF_SIZE);
    }

    memset(encrypted_key, 0, sizeof(encrypted_key));
    return 0;
}

int key_store_set (key_store_t ctx, const char* contact, const char* key)
{
    char encrypted_key[KEYBUF_SIZE] = { '\0' };

    encrypt_key(ctx->filekey, key, encrypted_key);

    int ret = setIniValue(contact, "key", encrypted_key, ctx->filepath);

    memset(encrypted_key, 0, sizeof(encrypted_key));

    return ret == 1 ? 0 : -1; // hack while setIniValue doesn't return 0
}

int key_store_unset (key_store_t ctx, const char* contact)
{
    deleteIniValue(contact, "key", ctx->filepath);

    return 0; // TODO(hpeixoto): deleteIniValue should probably return something.
}

int key_store_recrypt (key_store_t ctx, const char* new_password)
{
    char temp_filepath[512];
    char new_key[32];
    char new_hash[32];

    calculate_password_key_and_hash(new_password, new_key, new_hash);

    snprintf(temp_filepath, sizeof(temp_filepath), "%s_new", ctx->filepath);

    if (recrypt_ini_file(ctx->filepath, temp_filepath, ctx->filekey, new_key) < 0) {
        return -1;
    }

    if (new_password != NULL) {
        setIniValue("FiSH", "ini_password_Hash", new_hash, ctx->filepath);
    } else {
        deleteIniValue("FiSH", "ini_password_Hash", ctx->filepath);
    }

    free(ctx->filekey);
    ctx->filekey = strdup(new_key);

    return 0;
}

/* TODO: REWRITE THIS PLZ */
// Copyright unknown
static int recrypt_ini_file (
    const char* iniPath,
    const char* iniPath_new,
    const char* old_key,
    const char* new_key)
{
    FILE *h_ini = NULL;
    FILE *h_ini_new = NULL;
    char *fptr, *ok_ptr, line_buf[1000];
    char bfKey[512];
    int re_enc = 0;

    h_ini_new=fopen(iniPath_new, "w");
    h_ini=fopen(iniPath,"r");

    if (h_ini && h_ini_new) {
        while (!feof(h_ini)) {
            fptr=fgets(line_buf, sizeof(line_buf)-2, h_ini);
            if (fptr) {
                ok_ptr=strstr(line_buf, "+OK ");
                if (ok_ptr) {
                    re_enc=1;
                    strtok(ok_ptr+4, " \n\r");
                    decrypt_string(old_key, ok_ptr+4, bfKey, 512);
                    memset(ok_ptr+4, 0, strlen(ok_ptr+4)+1);
                    encrypt_string(new_key, bfKey, ok_ptr+4, strlen(bfKey));
                    strcat(line_buf, "\n");
                }
                if (fprintf(h_ini_new, "%s", line_buf) < 0) {
                    fclose(h_ini);
                    fclose(h_ini_new);
                    remove(iniPath_new);
                    memset(bfKey, 0, sizeof(bfKey));
                    memset(line_buf, 0, sizeof(line_buf));

                    return -1;
                }
            }
        }

        fclose(h_ini);
        fclose(h_ini_new);
        remove(iniPath);
        rename(iniPath_new, iniPath);
    }

    memset(bfKey, 0, sizeof(bfKey));
    memset(line_buf, 0, sizeof(line_buf));
    return re_enc;
}
/* TODO: END REWRITE */

static void calculate_password_key_and_hash (
    const char* a_password,
    char* a_key,
    char* a_hash)
{
    char key[32]  = { '\0' };
    char hash[32] = { '\0' };

    // This doesn't make much sense, but that's how it is.
    if (a_password != NULL) {
        key_from_password(a_password, key);
        htob64(key, a_key, 32);
    } else {
        strncpy(a_key, default_iniKey, 32);
    }

    key_hash(key, hash);
    htob64(hash, a_hash, 32);
}
