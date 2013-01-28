#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

int WritePrivateProfileString(const char *section, const char *key, const char *value, const char *filepath);
int GetPrivateProfileString(const char *section, const char *key, const char *default_value, char *buffer, int buflen, const char *filepath);
