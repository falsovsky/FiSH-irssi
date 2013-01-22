#include "cfgopts.h"
#include <glib.h>

int GetPrivateProfileString(const char *section, const char *key, const char *default_value, char *buffer, int buflen, const char *filepath)
{
    GKeyFile *key_file;
    GError *error;

    key_file = g_key_file_new();
    error = NULL;

    g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE, &error);
    if (error != NULL) goto default_value;

    if (g_key_file_get_string(key_file, section, key, &error) != NULL) {
        snprintf(buffer, buflen, "%s",  g_key_file_get_string(key_file, section, key, &error));
        return strlen(buffer);
    }

    default_value:
    if (error != NULL) {
        snprintf(buffer, buflen, "%s", default_value);
    }

    return strlen(buffer);
}

int WritePrivateProfileString(const char *section, const char *key, const char *value, const char *filepath)
{
    GKeyFile *key_file;
    GError *error;
    FILE *outfile;

    key_file = g_key_file_new();
    error = NULL;
    g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE, &error);

    if (error != NULL) {
        key_file = g_key_file_new();
    }

    g_key_file_set_string(key_file, section, key, value);

    outfile=fopen(filepath, "w");
    if (outfile == NULL) return -1;
    fprintf(outfile, "%s", g_key_file_to_data(key_file, NULL, NULL));
    fclose(outfile);

    return 1;
}
