
#include "fish2.h"

#include <stdio.h>
#include <assert.h>
#include <unistd.h>

void RUN (void (*name)(fish2_t)) {
  fish2_t ctx;
  unlink("test.ini");
  fish2_init(&ctx, "test.ini");
  name(ctx);
  fish2_deinit(ctx);
}

void test_nothing(fish2_t ctx) { }

void test_default_key(fish2_t ctx) {
  assert(!fish2_has_master_key(ctx));
  assert(fish2_validate_master_key(ctx, NULL) == 0);
}

void test_set_master_key(fish2_t ctx) {
  assert(!fish2_has_master_key(ctx));
  assert(!fish2_rekey(ctx, "megapotato"));
  assert(fish2_has_master_key(ctx));
  assert(fish2_validate_master_key(ctx, NULL) < 0);
  assert(fish2_validate_master_key(ctx, "megapotato") == 0);
}

void test_has_key(fish2_t ctx) {
  assert(fish2_validate_master_key(ctx, NULL) == 0);

  assert(fish2_has_key(ctx, "freenet", "nick") == 0);
  assert(fish2_set_key(ctx, "freenet", "nick", "mininikey") == 0);
  assert(fish2_has_key(ctx, "freenet", "nick") != 0);
}

void test_encrypt(fish2_t ctx) {
  char text[1024];

  assert(fish2_validate_master_key(ctx, NULL) == 0);
  assert(fish2_set_key(ctx, "freenet", "nick", "mininikey") == 0);
  assert(fish2_encrypt(ctx, "freenet", "nick", "hide your brains", text, sizeof(text)) == 0);

  printf("[%s]\n", text);
}

void test_roundtrip(fish2_t ctx) {
  char text[1024];
  char back[1024];

  assert(fish2_validate_master_key(ctx, NULL) == 0);
  assert(fish2_set_key(ctx, "freenet", "nick", "mininikey") == 0);

  assert(fish2_encrypt(ctx, "freenet", "nick", "hide your brains", text, sizeof(text)) == 0);
  assert(fish2_decrypt(ctx, "freenet", "nick", text, back, sizeof(back)) == 0);

  assert(strcmp(text, back));
  assert(!strcmp("hide your brains", back));
}

int main () {
  {
    fish2_t ctx;

    int ret = fish2_init(&ctx, "test.ini");
    printf("reting: %d\n", ret);

    fish2_deinit(ctx);
  }

  RUN(test_nothing);
  RUN(test_default_key);
  RUN(test_set_master_key);
  RUN(test_has_key);
  RUN(test_encrypt);
  RUN(test_roundtrip);

  return 0;
}
