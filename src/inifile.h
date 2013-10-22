#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

int setIniValue(const char *section, const char *key, const char *value,
		const char *filepath);
int getIniValue(const char *section, const char *key, const char *default_value,
		char *buffer, int buflen, const char *filepath);
void deleteIniValue(const char *section, const char *key, const char *filepath);
void writeIniFile(GKeyFile * key_file, const char *filepath);
