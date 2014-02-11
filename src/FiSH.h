#include "config.h.in"
#include "config.h"

#include "module.h"

/*
// Fix some warnings
#undef UOFF_T_INT
#undef UOFF_T_LONG
#undef UOFF_T_LONG_LONG
#undef PRIuUOFF_T
#undef SIZEOF_LONG
#undef SIZEOF_OFF_T

// irssi defines this, dont know why
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
*/

#define CONTACT_SIZE 100	// size of buffer for contactName (nick or #channel)
#define KEYBUF_SIZE 150		// size of buffer for base64 blowfish key (from blow.ini)

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)
#define IsNULLorEmpty(psz) (psz==NULL || *psz=='\0')
#define isNoChar(c) ((c) == 'n' || (c) == 'N' || (c) == '0')

// comment this out if you don't use ZNC
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


int ExtractRnick (char *Rnick, const char *incoming_msg);
char *strfcpy(char *dest, const char *buffer, int destSize);	// removes leading and trailing blanks from string

void DH1080_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target);
void DH1024_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target);
