#include "settings.h"
#include "inifile.h"

#include <core/settings.h>

struct settings_s {
};

struct setting_t {
    char name[32];
    char default_value[32];
};

static struct setting_t settings[] = {
  { "process_outgoing",  "1" },
  { "process_incoming",  "1" },
  { "auto_keyxchange",   "1" },
  { "nicktracker",       "1" },
  { "mark_broken_block", "1" },
  { "mark_encrypted",    "1" },
  { "mark_encrypted",    "" },
  { "mark_bloken_block", " \002&\002" }
};

#define isNoChar(c) ((c) == 'n' || (c) == 'N' || (c) == '0')

int fish2_settings_get_bool (
    fish2_t ctx,
    int field)
{
    char value[32];

    getIniValue(
        "FiSH",
        settings[field].name,
        settings[field].default_value,
        value,
        sizeof(value),
        ctx->filepath);

    return !isNoChar(*value);
}

int fish2_settings_get_string (
    fish2_t ctx,
    int field,
    char* output,
    size_t n)
{
    getIniValue(
        "FiSH",
        settings[field].name,
        settings[field].default_value,
        output,
        n,
        ctx->filepath);

    return 0;
}

void setup_irssi_settings() {
    settings_add_bool_module("fish", "fish", "process_outgoing", 1);
    settings_add_bool_module("fish", "fish", "process_incoming", 1);
    settings_add_bool_module("fish", "fish", "auto_keyxchange", 1);
    settings_add_bool_module("fish", "fish", "nicktracker", 1);

    settings_add_str_module("fish", "fish", "mark_broken_block", " \002&\002");
    settings_add_str_module("fish", "fish", "mark_encrypted", "\002>\002 ");
    settings_add_str_module("fish", "fish", "plain_prefix", "+p ");

    settings_add_int_module("fish", "fish", "mark_position", 1);
}
