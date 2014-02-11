#include "keyx.h"
#include "base64.h"

#include <stdlib.h>
#include <string.h>
#include <DH1080.h>

#define KEY_SIZE (1080/8*4/3) // 1080 bits in base64

struct keyx_s {
    dh1080_t dh_ctx;
    int running;

    // keys, with null terminator
    char my_private_key[KEY_SIZE+1];
    char my_public_key[KEY_SIZE+1];
};

int keyx_init (keyx_t* ctx)
{
    *ctx = (keyx_t)malloc(sizeof(struct keyx_s));
    if (*ctx == NULL) {
        return -1;
    }

    initb64();
    DH1080_Init(&(*ctx)->dh_ctx);

    (*ctx)->running = 0;

    return 0;
}

void keyx_deinit (keyx_t ctx)
{
  DH1080_DeInit(ctx->dh_ctx);
}

int keyx_start (keyx_t ctx)
{
  int ret = DH1080_gen(
      ctx->dh_ctx,
      ctx->my_private_key,
      ctx->my_public_key) == 0 ? -1 : 0;

  if (ret < 0) {
    return ret;
  }

  ctx->running = 1;

  return 0;
}

const char* keyx_public_key (keyx_t ctx)
{
    if (ctx->running) {
        return ctx->my_public_key;
    } else {
        return NULL;
    }
}

int keyx_running (keyx_t ctx)
{
    return ctx->running;
}

int keyx_finish (keyx_t ctx, const char* their_public_key, char* shared_key, size_t n)
{
  size_t their_public_key_length = strlen(their_public_key);

  if (their_public_key_length != KEY_SIZE || n < KEY_SIZE+1) {
      return -1;
  }

  if (!valid_b64(their_public_key, their_public_key_length)) {
     return -2;
  }

  // DH1080 needs a writable copy of their public key,
  // which will be overwritten with the shared key.
  strncpy(shared_key, their_public_key, n);
  shared_key[n-1] = 0;

  int ret = DH1080_comp(ctx->dh_ctx, ctx->my_private_key, shared_key) == 0 ? -1 : 0;

  if (ret < 0) {
      memset(shared_key, 0, n);
  }

  memset(ctx->my_private_key, 0, sizeof(ctx->my_private_key));
  ctx->running = 0;

  return ret;
}
