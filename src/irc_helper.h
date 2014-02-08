#ifndef IRC_HELPER_H_
#define IRC_HELPER_H_

#include <stdlib.h>

size_t irc_filter_controls (char* text, size_t n);

int irssi_target (
    const char* message,
    const char* nick,
    const char* target,
    char* contact,
    size_t n, const char** message_pointer);

#endif // IRC_HELPER_H_
