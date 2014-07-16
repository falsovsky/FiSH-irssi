#ifndef SETTINGS_H_
#define SETTINGS_H_

#define FISH2_SETTINGS_PROCESS_OUTGOING  0
#define FISH2_SETTINGS_PROCESS_INCOMING  1
#define FISH2_SETTINGS_AUTO_KEYEXCHANGE  2
#define FISH2_SETTINGS_NICKTRACKER       3
#define FISH2_SETTINGS_MARK_BROKEN_BLOCK 4
#define FISH2_SETTINGS_MARK_ENCRYPTION   5
#define FISH2_SETTINGS_ENCRYPTION_MARK   6
#define FISH2_SETTINGS_BROKEN_BLOCK_MARK 7

struct settings_s;
typedef struct settings_s* settings_t;

int settings_get_bool (
    settings_t ctx,
    int field);

int settings_get_string (
    settings_t ctx,
    int field,
    char* output,
    size_t n);

#endif // SETTINGS_H_
