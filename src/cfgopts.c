#include "cfgopts.h"
#include <glib.h>

int GetPrivateProfileString(const char *section, const char *key, const char *default_value, char *buffer, int buflen, const char *filepath)
{
    GKeyFile *key_file;
    GError *error;
    gchar *value = NULL;

    key_file = g_key_file_new();
    error = NULL;

    g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE, &error);

    // If file was read OK...
    if (error == NULL) { 
        // If the record was found...
        value = g_key_file_get_string(key_file, section, key, &error);
        if (value != NULL && error == NULL) {
            strncpy(buffer, g_key_file_get_string(key_file, section, key, NULL), buflen);
        }
    }

    g_free(value);

    // In case of any error...
    if (error != NULL) {
        strncpy(buffer, default_value, buflen);
    }

    return strlen(buffer);
}

int WritePrivateProfileString(const char *section, const char *key, const char *value, const char *filepath)
{
    GKeyFile *key_file;
    GError *error;
    FILE *outfile;
    gsize length;
    gchar *config = NULL;

    key_file = g_key_file_new();
    error = NULL;

    g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE, NULL);

    g_key_file_set_string(key_file, section, key, value);

    // Get the content of the config to a string...
    config = g_key_file_to_data(key_file, &length, &error);
    if (error == NULL) { // If everything is ok...
        outfile = fopen(filepath, "w");
        if (outfile != NULL) {
            fwrite(config, sizeof(gchar), length, outfile);
            fclose(outfile);
        }
    }

    g_free(config);
    if ((error != NULL) || (outfile == NULL)) {
        return -1;
    }

    return 1;
}
