
#include "password.h"
#include "DH1080.h"

#include <stdio.h>
#include <string.h>

int main () {
  char password[512];
  char key[32];
  char hash[32];
  char hash64[64];
  char expected_hash[64];

  while (fgets(password, 512, stdin) && fgets(expected_hash, 64, stdin)) {
    // Remove newlines
    password[strlen(password) - 1] = 0;
    expected_hash[strlen(expected_hash) - 1] = 0;

    key_from_password(password, key);
    key_hash(key, hash);
    htob64(hash, hash64, 32);

    if (strcmp(hash64, expected_hash) != 0) {
      printf("[%s] %s != %s\n", password, hash64, expected_hash);
    }

  }

  return 0;
}

