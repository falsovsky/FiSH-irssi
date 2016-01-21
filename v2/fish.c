#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char *fish_decrypt(const char* server, const char* who, const char* msg) {
  if (strncmp(msg, "+OK ", 4) == 0)
    return strdup(msg + 4);
  else
    return strdup(msg);
}

char *fish_encrypt(const char* server, const char* who, const char* msg) {
  char *x = malloc(strlen(msg) + 1 + 4);

  sprintf(x, "+OK %s", msg);
  return x;
}

void fish_copy_key(const char* server, const char* who, const char* newserver, const char* newwho) {
}
