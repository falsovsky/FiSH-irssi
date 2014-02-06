// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#include "fish2.h"
#include "key_store.h"
#include "inifile.h"

#include "fish2/blowcrypt.h"
#include "fish2/noop.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define KEYBUF_SIZE 150
#define CONTACT_SIZE 100

struct fish2_s {
  key_store_t key_store;
  char* prefix;
  char* filepath;
};

int fish2_init (
    fish2_t* ctx,
    const char* filepath,
    const char* filekey)
{
    (*ctx) = (fish2_t)malloc(sizeof(struct fish2_s));
    if (key_store_init(&(*ctx)->key_store, filepath, filekey) < 0) {
        free(*ctx);
        return -1;
    }

    (*ctx)->prefix = strdup("+ OK");
    (*ctx)->filepath = strdup(filepath);

    return 0;
}

void fish2_deinit (fish2_t ctx)
{
    key_store_deinit(ctx->key_store);
    free(ctx->prefix);
    free(ctx->filepath);
    free(ctx);
}

struct settings_t {
    char name[32];
    char default_value[32];
};

static struct settings_t settings[] = {
  { "process_outgoing", "1" },
  { "process_incoming", "1" },
  { "auto_keyxchange",  "1" },
  { "nicktracker",      "1" }
};

#define isNoChar(c) ((c) == 'n' || (c) == 'N' || (c) == '0')

int fish2_get_setting_bool (
    fish2_t ctx,
    int field)
{
    char value[32];

    getIniValue(
        "FiSH",
        settings[field].name,
        settings[field].default_value,
        value,
        sizeof(value),
        ctx->filepath);

    return !isNoChar(*value);
}

static int fish2_get_contact (
    fish2_t ctx,
    const char* server_tag,
    const char* target,
    char* contact)
{
    memset(contact, 0, CONTACT_SIZE);

    if (server_tag == NULL) {
        snprintf(contact, CONTACT_SIZE, "%s", target);
    } else {
        snprintf(contact, CONTACT_SIZE, "%s:%s", server_tag, target);
    }

    // Should INI fixing be here?
    return 0;
}

int fish2_has_key (
  fish2_t ctx,
  const char* server_tag,
  const char* receiver)
{
    return fish2_get_key(ctx, server_tag, receiver, NULL);
}

int fish2_get_key (
    fish2_t ctx,
    const char* server_tag,
    const char* receiver,
    char* key)
{
    char contact[CONTACT_SIZE] = { '\0' };

    if (fish2_get_contact(ctx, server_tag, receiver, contact) < 0) {
        return -1;
    }

    return key_store_get(ctx->key_store, contact, key);
}

typedef int (*decrypter_f)(
    const char*, const char*,
    size_t, char**, size_t*);

typedef int (*encrypter_f)(
    const char*, const char*,
    size_t, char**, size_t*);

struct decrypter_s {
    decrypter_f func;
    size_t offset;
};

struct encrypter_s {
    encrypter_f func;
    size_t offset;
};

static int fish2_get_decrypter (
    fish2_t ctx,
    const char* encrypted,
    size_t n,
    struct decrypter_s* decrypter)
{
    if (strncmp(encrypted, "+OK ", 4) == 0) {
      decrypter->func   = &fish2_blowfish_decrypt;
      decrypter->offset = 4;
      return 0;
    }

    if (strncmp(encrypted, "mcps ", 5) == 0) {
      decrypter->func   = &fish2_blowfish_decrypt;
      decrypter->offset = 5;
      return 0;
    }

    return -1;
}

static int fish2_get_encrypter (
    fish2_t ctx,
    const char* unencrypted,
    size_t n,
    struct encrypter_s* encrypter)
{
    if (strncmp(unencrypted, "+p ", 4) == 0) {
      encrypter->func   = &fish2_noop_encrypt;
      encrypter->offset = 4;
    } else {
      encrypter->func   = &fish2_blowfish_encrypt;
      encrypter->offset = 0;
    }

    return 0;
}

int fish2_encrypt (
    fish2_t ctx,
    const char* server_tag,
    const char* receiver,
    const char* plaintext,
    char* encrypted,
    size_t n)
{
    char key[KEYBUF_SIZE] = { '\0' };
    size_t input_size = strlen(plaintext);
    char* ciphertext = NULL;
    size_t ciphersize = 0;

    struct encrypter_s encrypter;
    if (fish2_get_encrypter(
          ctx,
          plaintext,
          input_size,
          &encrypter) < 0) {
        return -3;
    }

    if (fish2_get_key(ctx, server_tag, receiver, key) < 0) {
        return -1;
    }

    if (encrypter.func(
            key,
            plaintext + encrypter.offset,
            input_size - encrypter.offset,
            &ciphertext,
            &ciphersize) < 0) {
        return -2;
    }

    snprintf(encrypted, n, "%s%s", ctx->prefix, ciphertext);

    memset(key, 0, KEYBUF_SIZE);
    memset(ciphertext, 0, ciphersize);
    free(ciphertext);

    return 0;
}

int fish2_decrypt (
    fish2_t ctx,
    const char* server_tag,
    const char* sender,
    const char* encrypted,
    char* unencrypted,
    size_t n)
{
    char key[KEYBUF_SIZE] = { '\0' };
    size_t input_size = strlen(encrypted);
    char* plaintext = NULL;
    size_t plainsize = 0;

    struct decrypter_s decrypter;
    if (fish2_get_decrypter(
            ctx,
            encrypted,
            input_size,
            &decrypter) < 0) {
        return -3;
    }

    if (fish2_get_key(ctx, server_tag, sender, key) < 0) {
        return -1;
    }

    if (decrypter.func(
            key,
            encrypted + decrypter.offset,
            input_size - decrypter.offset,
            &plaintext,
            &plainsize) < 0) {
        return -2;
    }

    // TODO(hpeixoto): Apply mark_broken_block
    // TODO(hpeixoto): Apply mark_encrypted (mark_position)
    snprintf(unencrypted, n, "%s", plaintext);

    memset(key, 0, KEYBUF_SIZE);
    memset(plaintext, 0, plainsize);
    free(plaintext);

    return 0;
}
