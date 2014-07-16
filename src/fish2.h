// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#ifndef FISH2_H_
#define FISH2_H_

#include <stddef.h>

struct fish2_s;
typedef struct fish2_s* fish2_t;

// Context management
int fish2_init (
    fish2_t* ctx,
    const char* filepath);

void fish2_deinit (fish2_t ctx);

// Master password
int fish2_has_master_key (
    fish2_t ctx);

int fish2_validate_master_key (
    fish2_t ctx,
    const char* key);

int fish2_rekey (
    fish2_t ctx,
    const char* new_key);

// Settings
int fish2_get_setting_bool (
    fish2_t ctx,
    int field);

int fish2_get_setting_string (
    fish2_t ctx,
    int field,
    char* output,
    size_t n);

int fish2_get_user_setting_bool (
    fish2_t ctx,
    const char* server_tag,
    const char* contact,
    int field);

// Contact keys
int fish2_has_key (
    fish2_t ctx,
    const char* server_tag,
    const char* contact);

int fish2_get_key (
    fish2_t ctx,
    const char* server_tag,
    const char* contact,
    char* key);

int fish2_set_key (
    fish2_t ctx,
    const char* server_tag,
    const char* contact,
    const char* key);

int fish2_unset_key (
    fish2_t ctx,
    const char* server_tag,
    const char* contact);

// Ciphers
int fish2_encrypt (
    fish2_t ctx,
    const char* server_tag,
    const char* receiver,
    const char* plaintext,
    char* encrypted,
    size_t n);

int fish2_decrypt (
    fish2_t ctx,
    const char* server_tag,
    const char* sender,
    const char* encrypted,
    char* plaintext,
    size_t n);

int fish2_mark_encryption (
    fish2_t ctx,
    const char* server_tag,
    const char* sender,
    const char* plaintext,
    int broken,
    char* marked,
    size_t n);

#endif // FISH2_H_
