// Copyright (c) 2014 Hugo Peixoto, hugopeixoto.net

#ifndef KEY_STORE_H_
#define KEY_STORE_H_

struct key_store_s;
typedef struct key_store_s* key_store_t;

int key_store_init (key_store_t *ctx, const char* filepath);
void key_store_deinit (key_store_t ctx);

int key_store_has_master_key (key_store_t ctx);
int key_store_validate_master_key (key_store_t ctx, const char* password);

int key_store_recrypt (key_store_t ctx, const char* new_key);

int key_store_get (key_store_t ctx, const char* contact, char* key);
int key_store_set (key_store_t ctx, const char* contact, const char* key);
int key_store_unset (key_store_t ctx, const char* contact);

#endif // KEY_STORE_H_
