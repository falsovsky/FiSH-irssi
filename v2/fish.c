#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "blowfish.h"

static char* fish_getkey(const char* server, const char* who) {
  return strdup("potatochips");
}

static char* my_encrypt_string(const char* key, const char* msg) {
  char *encrypted = malloc(800);
  encrypt_string(key, msg, encrypted, strlen(msg));
  return encrypted;
}

static char* my_decrypt_string(const char* key, const char* msg) {
  char *decrypted = malloc(800);
  decrypt_string(key, msg, decrypted, strlen(msg));
  return decrypted;
}


char *fish_decrypt(const char* server, const char* who, const char* msg) {
  char *key = fish_getkey(server, who);
  char *plaintext;

  if (strncmp(msg, "+OK ", 4) == 0) {
    char *decrypted = my_decrypt_string(key, msg + 4);

    plaintext = malloc(strlen(decrypted) + 1);
    sprintf(plaintext, "%s", decrypted);
    free(decrypted);
  } else
    plaintext = strdup(msg);

  free(key);
  return plaintext;
}

char *fish_encrypt(const char* server, const char* who, const char* msg) {
  char *key = fish_getkey(server, who);

  char *encrypted = my_encrypt_string(key, msg);

  char *ciphertext = malloc(4 + strlen(encrypted) + 1);
  sprintf(ciphertext, "+OK %s", encrypted);
  free(encrypted);

  free(key);
  return ciphertext;
}

void fish_copy_key(const char* server, const char* who, const char* newserver, const char* newwho) {
}
