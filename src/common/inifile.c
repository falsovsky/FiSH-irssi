#include "inifile.h"

/**
 * @file   inifile.c
 * @brief  Handles reading and writing to blow.ini
 *
 * These functions implement a config file based on GLib GKeyFile
 * http://developer.gnome.org/glib/2.32/glib-Key-value-file-parser.html
 *
 * A normal blow.ini looks something like this:
 * @code
 * [EFNet:#zbr]
 * key=+OK IxH39/AbJUH/aRUx614KBmA.XkCgI/pV30Q.Fntj81tJF.Z1j3qP91n8Ogs1i.h0/1w2uqO0
 *
 * [EFNet:Jarbas]
 * key=+OK 1m4r7//QR9O10.bHc/J5I54/y31qm0eTQne1ztw170pz8500B16PD0G5C1G0/1gHm/QcANO/
 *
 * [FiSH]
 * ini_password_Hash=kHmWjS7BL+IffmLCJ+JWMj9y5r9mb+yioTm8oE/RmEw
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
 * getIniValue("EFNet:#zbr", "key", "", tmpKey, KEYBUF_SIZE, iniPath);
 *
 * // Get the plain_prefix variable from the FiSH section, defaulting to "+p " if non-existant
 * getIniValue("FiSH", "plain_prefix", "+p ", plainPrefix, sizeof(plainPrefix), iniPath);
 * @endcode
 */
    int
getIniValue(const char *section, const char *key, const char *default_value,
        char *buffer, int buflen, const char *filepath)
{
    GKeyFile *key_file;
    GError *error = NULL;
    gchar *value = NULL;

    key_file = g_key_file_new();

    // If file was read OK...
    if ((int)
            g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE,
                NULL) == 1) {
        // If the record was found...
        value = g_key_file_get_string(key_file, section, key, &error);
        if (value != NULL && error == NULL) {
            strncpy(buffer, value, (size_t) buflen);
            buffer[buflen] = '\0';
        }
    }

    g_free(value);
    g_key_file_free(key_file);

    // In case of any error...
    if (error != NULL) {
        g_error_free(error);
        strncpy(buffer, default_value, (size_t) buflen);
    }

    return (int)strlen(buffer);
}

int getIniSize(const char *section, const char *key, const char *filepath)
{
    GKeyFile *key_file;
    GError *error = NULL;
    gchar *value = NULL;
    int size = 1;

    key_file = g_key_file_new();

    if ((int)
            g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE,
                NULL) == 1) {
        value = g_key_file_get_string(key_file, section, key, &error);
        if (value != NULL && error == NULL) {
            size = strlen(value);
        }
    }

    g_free(value);
    g_key_file_free(key_file);

    return size;
}

int deleteIniValue(const char *section, const char *key, const char *filepath)
{
    GKeyFile *key_file;
    GError *error = NULL;
    gsize num_keys = 0;
    int ret = 0;

    key_file = g_key_file_new();

    // If file was read OK...
    if ((int)
            g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE,
                NULL) == 1) {
        g_key_file_remove_key(key_file, section, key, &error);
        if (error == NULL) {
            // Check if group is empty, if it is, remove it also
            (void)g_key_file_get_keys(key_file, section, &num_keys,
                    &error);
            if (error == NULL && num_keys == 0) {
                g_key_file_remove_group(key_file, section,
                        NULL);

                writeIniFile(key_file, filepath);
            }
            ret = 1;
        } else {
            ret = 0;
        }
    }

    g_key_file_free(key_file);

    return ret;
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
 * setIniValue("FiSH", "plain_prefix", "+zbr ", iniPath);
 * @endcode
 */
    int
setIniValue(const char *section, const char *key, const char *value,
        const char *filepath)
{
    GKeyFile *key_file;
    GError *error = NULL;

    key_file = g_key_file_new();
    (void)g_key_file_load_from_file(key_file, filepath, G_KEY_FILE_NONE,
                                    &error);
    g_key_file_set_string(key_file, section, key, value);

    writeIniFile(key_file, filepath);

    g_key_file_free(key_file);

    if (error != NULL) {
        g_error_free(error);
        return -1;
    }

    return 1;
}

void writeIniFile(GKeyFile * key_file, const char *filepath)
{
    gchar *config = NULL;
    GError *error = NULL;
    gsize length = 0;
    FILE *outfile = NULL;

    // Get the content of the config to a string...
    config = g_key_file_to_data(key_file, &length, &error);
    if (error == NULL) { // If everything is ok...
        outfile = fopen(filepath, "w");
        if (outfile != NULL) {
            (void)fwrite(config, sizeof(gchar), (size_t) length,
                    outfile);
            (void)fclose(outfile);
        }
    }

    g_free(config);
}

    struct IniValue
allocateIni(const char *section, const char *key, const char *filepath)
{
    struct IniValue iniValue;

    iniValue.iniKeySize = getIniSize(section, key, filepath);
    iniValue.keySize = (iniValue.iniKeySize * 2) * sizeof(char);
    iniValue.key = (char *)malloc(iniValue.keySize);

    return iniValue;
}

void freeIni(struct IniValue iniValue)
{
    bzero(iniValue.key, iniValue.keySize);
    free(iniValue.key);
}

int cryptIni(const char *iniPath, const char *iniPath_new,
                     const char *iniKey_old, const char *iniKey)
{
    GKeyFile *config = g_key_file_new();
    GError *error = NULL;
    int newKeySize, oldKeySize, plusOkSize, result = 0;
    char *newKey, *oldKey, *plusOk;

    /* Try to read the file */
    g_key_file_load_from_file(config, iniPath, G_KEY_FILE_NONE, &error);
    if (error != NULL) {
        g_error_free(error);
        error = NULL;
        g_key_file_free(config);
        return -1;
    }

    /* Get a list of all the groups */
    int groupIndex;
    gsize groupsSize = 0;
    gchar **groups = g_key_file_get_groups(config, &groupsSize);
    /* Iterate over all the groups */
    for (groupIndex = 0; groupIndex < groupsSize; groupIndex++) {
        /* Get a list of all the keys */
        gsize keysCount = 0;
        gchar **keys = g_key_file_get_keys(config, groups[groupIndex], &keysCount, &error);

        if (error != NULL) {
            g_error_free(error);
            error = NULL;
            continue;
        }

        /* Iterate over all the keys */
        int keysIndex;
        for (keysIndex = 0; keysIndex < keysCount; keysIndex++) {

            /* Get key value */
            gchar *value = g_key_file_get_value(config, groups[groupIndex], keys[keysIndex], &error);

            if (error != NULL) {
                g_error_free(error);
                error = NULL;
                continue;
            }

            if (strncmp(value, "+OK ", 4) == 0) {
                result = 1;

                /* Decrypt value using iniKey_old */
                oldKeySize = (strlen(value) * 2) * sizeof(char);
                oldKey = (char *) malloc(oldKeySize);
                decrypt_string(iniKey_old, value + 4, oldKey, strlen(value + 4));

                /* Encrypt value using iniKey */
                newKeySize = (strlen(oldKey) * 2)* sizeof(char);
                newKey = (char *) malloc(newKeySize);
                encrypt_string(iniKey, oldKey, newKey, strlen(oldKey));

                /* Prefix "+OK " to value */
                plusOkSize = (strlen(newKey) * 2) * sizeof(char);
                plusOk = (char *) malloc(plusOkSize);
                snprintf(plusOk, plusOkSize, "+OK %s", newKey);

                /* Set value on iniPath_new */
                setIniValue(groups[groupIndex], keys[keysIndex], plusOk, iniPath_new);

                bzero(oldKey, oldKeySize);
                free(oldKey);
                bzero(newKey, newKeySize);
                free(newKey);
                bzero(plusOk, plusOkSize);
                free(plusOk);
            }

            g_free(value);
        }

        g_strfreev(keys);
    }

    g_strfreev(groups);
    g_key_file_free(config);

    /* Delete original file and rename the new one */
    remove(iniPath);
    rename(iniPath_new, iniPath);

    return result;
}