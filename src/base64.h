#ifndef BASE64_H_
#define BASE64_H_

void initb64 ();
int b64toh(const char *b, char *d);
int htob64(const char *h, char *d, unsigned int l);
int valid_b64(const char *str, int len);

#endif // BASE64_H_
