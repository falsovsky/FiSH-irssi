#ifndef KEYX_H_
#define KEYX_H_

#include <stddef.h>

struct keyx_s;
typedef struct keyx_s* keyx_t;

int keyx_init (keyx_t* ctx);
void keyx_deinit (keyx_t ctx);

int keyx_start (keyx_t ctx);

const char* keyx_public_key (keyx_t ctx);
int keyx_running (keyx_t ctx);

int keyx_finish (keyx_t ctx, const char* their_public_key, char* shared_key, size_t n);

#endif // KEYX_H_
