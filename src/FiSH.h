#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "FiSH_version.h"
#include "inifile.h"
#include "blowfish.h"
#include "DH1080.h"
#include "module.h"

#define CONTACT_SIZE 100	// size of buffer for contactName (nick or #channel)
#define KEYBUF_SIZE 150		// size of buffer for base64 blowfish key (from blow.ini)

#define ZeroMemory(dest,count) memset((void *)dest, 0, count)
#define IsNULLorEmpty(psz) (psz==NULL || *psz=='\0')
#define isNoChar(c) ((c) == 'n' || (c) == 'N' || (c) == '0')

int ExtractRnick(char *Rnick, char *incoming_msg);
void FixIniSection(const char *section, char *fixedSection);	// replace '[' and ']' in nick/channel with '~'
int GetBlowIniSwitch(const char *section, const char *key,
        const char *default_value);
char *isPlainPrefix(const char *msg);
char *strfcpy(char *dest, char *buffer, int destSize);	// removes leading and trailing blanks from string

void DH1080_received(SERVER_REC * server, char *msg, char *nick, char *address,
        char *target);

const char blow_ini[] = "/blow.ini";
char iniPath[255];
char *iniKey = NULL;
int iniUsed = 0;
char g_myPrivKey[300], g_myPubKey[300];

int keyx_query_created = 0;
