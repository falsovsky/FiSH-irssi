
#include "fish2.h"

#include <stdio.h>
#include <assert.h>
#include <unistd.h>

static const char sample[] = "hide your brains";

void RUN (void (*name)(fish2_t)) {
  fish2_t ctx;
  unlink("test.ini");
  assert(fish2_init(&ctx, "test.ini") == 0);
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
  assert(fish2_unset_key(ctx, "freenet", "nick") == 0);
  assert(fish2_has_key(ctx, "freenet", "nick") == 0);
}

void test_encrypt(fish2_t ctx) {
  char text[1024];

  assert(fish2_validate_master_key(ctx, NULL) == 0);
  assert(fish2_set_key(ctx, "freenet", "nick", "mininikey") == 0);
  assert(fish2_encrypt(ctx, "freenet", "nick", sample, text, sizeof(text)) == 0);

  printf("[%s]\n", text);
}

void test_roundtrip(fish2_t ctx) {
  char text[1024];
  char back[1024];

  assert(fish2_validate_master_key(ctx, NULL) == 0);
  assert(fish2_set_key(ctx, "freenet", "nick", "mininikey") == 0);

  assert(fish2_encrypt(ctx, "freenet", "nick", sample, text, sizeof(text)) == 0);
  assert(fish2_decrypt(ctx, "freenet", "nick", text, back, sizeof(back)) == 0);

  assert(strcmp(text, back));
  assert(!strcmp(sample, back));
}

void test_mark(fish2_t ctx) {
  char text[1024];

  assert(fish2_validate_master_key(ctx, NULL) == 0);
  assert(fish2_set_key(ctx, "freenet", "nick", "mininikey") == 0);

  assert(fish2_mark_encryption(ctx, "freenet", "nick", sample, 0, text, sizeof(text)) == 0);
}

int main () {
  int i;
  int n = 10;
  for (i = 0; i < n; ++i) {
    RUN(test_nothing);
    RUN(test_default_key);
    RUN(test_set_master_key);
    RUN(test_has_key);
    RUN(test_encrypt);
    RUN(test_roundtrip);
    RUN(test_mark);
  }

  return 0;
}
