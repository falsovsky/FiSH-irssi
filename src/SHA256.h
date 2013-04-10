#ifndef SHA256_H_
#define SHA256_H_

void SHA256_memory(char *buf, const int len, const char *hash);
int sha_file(const char *filename, const char *hash);

#endif // SHA256_H_
