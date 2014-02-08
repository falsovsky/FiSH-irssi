#include "irc_helper.h"

#include <common.h>
#include <irc/core/irc.h>

#include <string.h>
#include <stdio.h>

size_t irc_filter_controls (char* text, size_t n)
{
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < n; ++i) {
        char p = text[i];
        text[i] = '\0';
        text[j] = p;
        if (p != 0x0A && p != 0x0D && p != 0x00) {
          ++j;
        }
    }

    return j;
}

/*
 * :someone!ident@host.net PRIVMSG leetguy :Some Text -> Result: Rnick="someone"
 * needs direct pointer to "nick@host" or ":nick@host"
 */
static int ExtractRnick (char *Rnick, const char *msg, size_t n)
{
    size_t k=0;

    if (*msg==':' || *msg==' ') msg++;

    while (*msg!='!' && *msg!='\0' && *msg!=' ' && k < n) {
        Rnick[k]=*msg;
        msg++;
        k++;
    }
    Rnick[k]='\0';

    if (*Rnick != '\0') return 1;
    else return 0;
}

static int extract_psybnc (const char* message, char* contact, size_t n, const char** message_start)
{
    // psyBNC log message found:
    // <-psyBNC> Nw~Thu Mar 29 15:02:45 :(yourmom!ident@get.se) +OK e3454451hbadA0

    message = strstr(message, " :("); // points to nick!ident@host in psybnc log
    if (!message) return -2;

    message += 3;

    ExtractRnick(contact, message, n);

    message = strchr(message, ' ');
    if (!message) return -3;

    *message_start = message;
    return 0;
}

static int extract_sbnc (const char* message, char* contact, size_t n, const char** message_start)
{
    // sBNC log message found:
    // <-sBNC> Sun Sep  1 13:37:00 2007 someone (some@one.us): +OK Mp1p8.qYxFN1
    const char* start = message;

    message = strstr(message, " (");
    if (!message) return -4;

    for (--message; start < message && *message != ' '; --message);
    ++message; // now points to the first char of the nick

    ExtractRnick(contact, message, n);

    *message_start = strstr(message, "): ");
    if (!message) return -5;

    *message_start += 3;
    return 0;
}

int irssi_target (
    const char* message,
    const char* nick,
    const char* target,
    char* contact,
    size_t n,
    const char** message_pointer)
{
    if (!message || !nick || !target) return -1; // Why would this even happen?

#ifdef FiSH_DECRYPT_ZNC_LOGS
    if (IsZNCtimestamp(message)) message += 11;
#endif

    //channel?
    if (ischannel(*target)) {
        *message_pointer = message;
        snprintf(contact, n, "%s", target);
        return 0;

    } else if (!strcmp(nick, "-psyBNC")) {
        return extract_psybnc(message, contact, n, message_pointer);

    } else if (!strcmp(nick, "-sBNC")) {
        return extract_sbnc(message, contact, n, message_pointer);

    } else {
        *message_pointer = message;
        snprintf(contact, n, "%s", nick);
        return 0;
    }
}
