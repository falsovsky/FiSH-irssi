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

// Exported module functions
void fish_init ();
void fish_deinit ();


void DH1080_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target);
void DH1024_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target);
