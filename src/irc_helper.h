#ifndef IRC_HELPER_H_
#define IRC_HELPER_H_

#include <stddef.h>

// define FiSH_DECRYPT_ZNC_LOGS if you use ZNC
// #define FiSH_DECRYPT_ZNC_LOGS

#ifdef FiSH_DECRYPT_ZNC_LOGS
// ZNC logs timestamp "[14:13:43] +OK oUICg.tehx71..."
#define IsZNCtimestamp(msg) \
		msg[0] == '[' && \
		isdigit(msg[1]) && isdigit(msg[2]) && \
		msg[3] == ':' && \
		isdigit(msg[4]) && isdigit(msg[5]) && \
		msg[6] == ':' && \
		isdigit(msg[7]) && isdigit(msg[8]) && \
		msg[9] == ']' && msg[10] == ' '
#endif


size_t irc_filter_controls (char* text, size_t n);

// detects message contact (channel or nick).
// It uses some heuristics to determine if the
// incoming message is a psyBNC or sBNC log
//
// TODO(hpeixoto): It would be ideal to discard
// the irssi dependency on ischannel.
int irssi_target (
    const char* message,
    const char* nick,
    const char* target,
    char* contact,
    size_t n, const char** message_pointer);

// removes leading and trailing blanks from string
char *strfcpy(char *dest, const char *buffer, int destSize);

#endif // IRC_HELPER_H_
