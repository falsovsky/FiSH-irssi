#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "blowfish.h"

struct IniValue {
    char *key;
    int iniKeySize;
    int keySize;
    int cbc;
};

int setIniValue(const char *section, const char *key, const char *value,
        const char *filepath);
int getIniValue(const char *section, const char *key,
        const char *default_value, char *buffer, int buflen,
        const char *filepath);
int getIniSize(const char *section, const char *key, const char *filepath);
int deleteIniValue(const char *section, const char *key, const char *filepath);
void writeIniFile(GKeyFile * key_file, const char *filepath);
struct IniValue allocateIni(const char *section, const char *key,
        const char *filepath);
void freeIni(struct IniValue iniValue);
int cryptIni(const char *iniPath, const char *iniPath_new,
             const char *iniKey_old, const char *iniKey);