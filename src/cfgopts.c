#include "cfgopts.h"

#ifdef S_SPLINT_S
#include "splint.h"
#endif
/**
 * @file   cfgopts.c
 * @brief  Handles reading and writing to blow.ini
 *
 * These functions implement a config file based on GLib GKeyFile
 * http://developer.gnome.org/glib/2.32/glib-Key-value-file-parser.html
 *
 * A normal blow.ini looks something like this:
 * @code
 * [FiSH]
 * plain_prefix="+p "
 * process_incoming=1
 * process_outgoing=1
 *
 * [EFNet:#zbr]
 * key=+OK IxH39/AbJUH/aRUx614KBmA.XkCgI/pV30Q.Fntj81tJF.Z1j3qP91n8Ogs1i.h0/1w2uqO0
 *
 * [EFNet:Jarbas]
 * key=+OK 1m4r7//QR9O10.bHc/J5I54/y31qm0eTQne1ztw170pz8500B16PD0G5C1G0/1gHm/QcANO/
 * @endcode
 */

/**
 * Read a key from blow.ini
 * @param [in] section configuration value
 * @param [in] key configuration key
 * @param [in] default_value default value to write in buffer if something bad happens
 * @param [out] buffer key
 * @param [in] buflen length of buffer
 * @param [in] filepath file path to blow.ini
 * @return the length of the buffer
 *
 * Example Usage:
 * @code
 * char tmpKey[KEYBUF_SIZE]="";
 * char plainPrefix[20]="";
 *
 * // Reads the key for #zbr at EFNet
 * GetPrivateProfileString("EFNet:#zbr", "key", "", tmpKey, KEYBUF_SIZE, iniPath);
 *
 * // Get the plain_prefix variable from the FiSH section, defaulting to "+p " if non-existant
 * GetPrivateProfileString("FiSH", "plain_prefix", "+p ", plainPrefix, sizeof(plainPrefix), iniPath);
 * @endcode
 */
int GetPrivateProfileString(const char *section, const char *key, const char *default_value, char *buffer, int buflen, const char *filepath)
{
    GKeyFile *key_file;
    GError *error = NULL;
    gchar *value = NULL;

    key_file = g_key_file_new();

    // If file was read OK...
    if ((int) g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE, NULL)==1) {
        // If the record was found...
        value = g_key_file_get_string(key_file, section, key, &error);
        if (value != NULL && error == NULL) {
            strncpy(buffer, value, (size_t)buflen);
        }
    }

    g_free(value);
    g_key_file_free(key_file);

    // In case of any error...
    if (error != NULL) {
        strncpy(buffer, default_value, (size_t)buflen);
    }

    return (int) strlen(buffer);
}

/**
 * Write a key to blow.ini
 * @param [in] section configuration section
 * @param [in] key configuration key
 * @param [in] value value to write
 * @param [in] filepath file path to blow.ini
 * @return 1 if everything is ok -1 if not
 *
 * Example Usage:
 * @code
 * // Set the plain_prefix variable as "+zbr "
 * WritePrivateProfileString("FiSH", "plain_prefix", "+zbr ", iniPath);
 * @endcode
 */
int WritePrivateProfileString(const char *section, const char *key, const char *value, const char *filepath)
{
    GKeyFile *key_file;
    GError *error = NULL;
    FILE *outfile = NULL;
    gsize length = 0;
    gchar *config = NULL;

    key_file = g_key_file_new();

    (void) g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE, NULL);
    g_key_file_set_string(key_file, section, key, value);

    // Get the content of the config to a string...
    config = g_key_file_to_data(key_file, &length, &error);
    if (error == NULL) { // If everything is ok...
        outfile = fopen(filepath, "w");
        if (outfile != NULL) {
            (void) fwrite(config, sizeof(gchar), (size_t) length, outfile);
            (void) fclose(outfile);
        }
    }

    g_free(config);
    g_key_file_free(key_file);

    if ((error != NULL) || (outfile == NULL)) {
        return -1;
    }

    return 1;
}

