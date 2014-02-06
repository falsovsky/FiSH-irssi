// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#ifndef FISH2_H_
#define FISH2_H_

#include <stdlib.h>

#define FISH2_PROCESS_OUTGOING  0
#define FISH2_PROCESS_INCOMING  1
#define FISH2_AUTO_KEYEXCHANGE  2
#define FISH2_NICKTRACKER       3
#define FISH2_MARK_BROKEN_BLOCK 4
#define FISH2_MARK_ENCRYPTION   5
#define FISH2_ENCRYPTION_MARK   6
#define FISH2_BROKEN_BLOCK_MARK 7

struct fish2_s;
typedef struct fish2_s* fish2_t;

int fish2_init (
    fish2_t* ctx,
    const char* filepath,
    const char* filekey);

void fish2_deinit (fish2_t ctx);

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

int fish2_has_key (
    fish2_t ctx,
    const char* server_tag,
    const char* contact);

int fish2_get_key (
    fish2_t ctx,
    const char* server_tag,
    const char* contact,
    char* key);

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
