#include "cfgopts.h"
#include "blowfish.h"
#include "DH1080.h"

#include <time.h>
#include <unistd.h>

#include "module.h"


#define CONTACT_SIZE 100	// size of buffer for contactName (nick or #channel)
#define KEYBUF_SIZE 150		// size of buffer for base64 blowfish key (from blow.ini)

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)
#define IsNULLorEmpty(psz) (psz==NULL || *psz=='\0')
#define isNoChar(c) ((c) == 'n' || (c) == 'N' || (c) == '0')

// comment this out if you don't use ZNC
#define FiSH_DECRYPT_ZNC_LOGS

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


// use irssi recode feature?
#define FiSH_USE_IRSSI_RECODE


//int ExtractRhost (char *Rhost, char *incoming_msg);
int ExtractRnick (char *Rnick, char *incoming_msg);
void FixIniSection(const char *section, char *fixedSection);	// replace '[' and ']' in nick/channel with '~'
int GetBlowIniSwitch(const char *section, const char *key, const char *default_value);
char *IsPlainPrefix(const char *msg);
char *strfcpy(char *dest, char *buffer, int destSize);	// removes leading and trailing blanks from string


void DH1080_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target);


const char default_iniKey[]="blowinikey", blow_ini[]="/blow.ini";
char iniKey[100], iniPath[255], tempPath[255];
char g_myPrivKey[300], g_myPubKey[300];

BOOL unsetiniFlag=0, keyx_query_created=0;
