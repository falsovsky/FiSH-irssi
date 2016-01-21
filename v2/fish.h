#ifndef V2_FISH_H_
#define V2_FISH_H_

char *fish_decrypt(const char* server, const char* who, const char* msg);
char *fish_encrypt(const char* server, const char* who, const char* msg);
void fish_copy_key(const char* server, const char* who, const char* newserver, const char* newwho);

#endif
