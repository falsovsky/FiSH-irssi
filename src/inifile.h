#ifndef INIFILE_H_
#define INIFILE_H_

#include <stddef.h>

int setIniValue(const char *section, const char *key, const char *value, const char *filepath);
int getIniValue(const char *section, const char *key, const char *default_value, char *buffer, int buflen, const char *filepath);
void deleteIniValue(const char *section, const char *key, const char *filepath);
void FixIniSection(const char *section, char *fixedSection, size_t n);

#endif // INIFILE_H_
