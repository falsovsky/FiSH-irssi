#ifndef BLOWFISH_H_
#define BLOWFISH_H_

// 0 for error, 1  for success

int decrypt_string(const char *key, const char *str, char *dest, int len);
int encrypt_string(const char *key, const char *str, char *dest, int len);

#endif // BLOWFISH_H_
