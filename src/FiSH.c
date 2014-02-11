// FiSH encryption module for irssi, v1.00
// Copyright: Mostly unknown

#include "FiSH.h"

#include "fish2.h"
#include "keyx.h"
#include "irc_helper.h"

#ifdef S_SPLINT_S
#include "splint.h"
#endif

// Static context information
static keyx_t keyx_ctx;
static fish2_t fish2_ctx;

static int keyx_query_created = 0;

static const char* server_tag (const SERVER_REC* server)
{
    if (server == NULL) {
        return NULL;
    } else {
        return server->tag;
    }
}

size_t irssi_recode_text (
    char* text, size_t n,
    const SERVER_REC* server,
    const char* target,
    size_t max_n)
{
#ifdef FiSH_USE_IRSSI_RECODE
    char* recoded = NULL;

    if (settings_get_bool("recode") && server != NULL) {
        recoded = recode_in(server, text, target);
        if (recoded) {
            strncpy(text, recoded, max_n);
            text[max_n-1] = '\0';

            memset(recoded, 0, strlen(recoded));
            g_free(recoded);
        }
    }
#endif

    return strlen(text);
}

/*
 * Encrypt a message and store in bf_dest (using key for target)
 * @param server
 * @param msg_ptr
 * @param target
 * @param bf_dest
 * @return 1 if everything ok 0 if not
 */
int FiSH_encrypt(
    const SERVER_REC *serverRec,
    const char* msgPtr,
    const char* target,
    char* bf_dest,
    size_t n)
{
    if (!fish2_get_setting_bool(
            fish2_ctx,
            FISH2_PROCESS_OUTGOING)) {
        return 0;
    }

    int ret = fish2_encrypt(
        fish2_ctx,
        server_tag(serverRec),
        target,
        msgPtr,
        bf_dest,
        n);

    return ret == 0 ? 1 : 0;
}

/*
 * Decrypt a base64 cipher text (using key for target)
 */
int FiSH_decrypt (
    const SERVER_REC *serverRec,
    char *msg_ptr,
    char *msg_bak,
    const char *target)
{
    char bf_dest[1000];

    if (!fish2_get_setting_bool(
          fish2_ctx,
          FISH2_PROCESS_INCOMING)) {
      return 0;
    }

    if (fish2_decrypt(
            fish2_ctx,
            server_tag(serverRec),
            target,
            msg_ptr,
            bf_dest,
            1000) < 0) {
        return 0;
    }

    // Recode message, feature (irssi)
    irssi_recode_text(bf_dest, 1000, serverRec, target, 1000);

    // Strip dangerous characters: 0x0A, 0x0D, 0x00 (irssi)
    // In case of wrong key, it might have control characters
    irc_filter_controls(bf_dest, 1000);

    // copy decrypted message back
    // (overwriting the base64 cipher text)
    strcpy(msg_bak, bf_dest);

    return 1;
}

void decrypt_msg (SERVER_REC *server, char *msg, const char *nick, const char *address, const char *target)
{
    const char *msg_bak=msg;
    char contact[CONTACT_SIZE]="";

    const char* xpto;
    if (irssi_target(msg, nick, target, contact, CONTACT_SIZE, &xpto) < 0)
        return;

    if (FiSH_decrypt(server, msg, msg, contact)) {
        return;
        if (strncmp(msg_bak, "\001ACTION ", 8)==0) {
            // ACTION message found
            signal_stop();
            signal_emit("message irc action", 5, server, msg_bak+8, nick, address, target);
        }
    }
}

void encrypt_msg(SERVER_REC *server, char *target, char *msg, char *orig_target)
{
    char bf_dest[512] = { '\0' };

    if (FiSH_encrypt(server, msg, target, bf_dest, sizeof(bf_dest)) == 1) {
        signal_continue(4, server, target, bf_dest, orig_target);
    }

    memset(bf_dest, 0, sizeof(bf_dest));
}

/*
 * Format outgoing (encrypted) messages.
 * This adds a crypt-mark or removes plain-prefix
 */
void format_msg(SERVER_REC *server, char *msg, char *target, char *orig_target)
{
    char formattedMsg[800] = { '\0' };

    if (!fish2_get_setting_bool(fish2_ctx, FISH2_PROCESS_OUTGOING)) return;

    if (fish2_mark_encryption(
        fish2_ctx,
        server_tag(server),
        target,
        msg,
        0,
        formattedMsg,
        sizeof(formattedMsg)) < 0) {
        return;
    }

    signal_continue(4, server, formattedMsg, target, orig_target);
    memset(formattedMsg, 0, sizeof(formattedMsg));
}

/*
 * Decrypt NOTICE messages (and forward DH1080 key-exchange)
 */
void decrypt_notice(SERVER_REC *server, char *msg, char *nick, char *address, char *target)
{
    const char *DH1024warn;

    if (strncmp(msg, "DH1024_", 7)==0) {
        DH1024warn = "\002FiSH:\002 Received \002old DH1024\002 public key from you! Please update to latest version: https://github.com/falsovsky/FiSH-irssi";
        signal_stop();
        irc_send_cmdv((IRC_SERVER_REC *)server, "NOTICE %s :%s\n", nick, DH1024warn);
        signal_emit("message irc own_notice", 3, server, DH1024warn, nick);
        return;
    }

    if (strncmp(msg, "DH1080_", 7)==0) {
        DH1080_received(server, msg, nick, address, target);
        return;
    }

#ifdef FiSH_DECRYPT_ZNC_LOGS
    if (IsZNCtimestamp(msg)) msg += 11;
#endif

    FiSH_decrypt(server, msg, msg, ischannel(*target) ? target : nick);
}

void decrypt_action(SERVER_REC *server, char *msg, char *nick, char *address, char *target)
{
    if (target==NULL) return;

    FiSH_decrypt(server, msg, msg, ischannel(*target) ? target : nick);
}

void decrypt_topic (SERVER_REC *server, char *channel, char *topic, char *nick, char *address)
{
    FiSH_decrypt(server, topic, topic, channel);
}

void decrypt_changed_topic(CHANNEL_REC *chan_rec)
{
    FiSH_decrypt(chan_rec->server, chan_rec->topic, chan_rec->topic, chan_rec->name);
}

void raw_handler(SERVER_REC *server, char *data)
{
    char channel[CONTACT_SIZE], *ptr, *ptr_bak;
    int len;

    if (IsNULLorEmpty(data)) return;

    ptr=strchr(data, ' ');	// point to command
    if (ptr==NULL) return;
    ptr++;

    if (strncmp(ptr, "332 ", 4)!=0) return;	// 332 = TOPIC

    ptr_bak=ptr;
    ptr=strchr(ptr, '#');	// point to #channel
    if (ptr==NULL) {
        ptr=strchr(ptr_bak, '&');	// point to &channel
        if (ptr==NULL) {
            ptr=strchr(ptr_bak, '!');	// point to !channel
            if (ptr==NULL) return;
        }
    }

    len=strchr(ptr, ' ')-ptr;
    if (len >= CONTACT_SIZE-2) return;	// channel string too long, something went wrong
    strncpy(channel, ptr, len);
    channel[len]='\0';

    ptr=strchr(ptr, ':');	// point to topic msg start
    if (ptr==NULL) return;
    ptr++;

    FiSH_decrypt(server, ptr, ptr, channel);
}

/*
 * New command: /notice+ <nick/#channel> <notice message>
 */
void cmd_crypt_notice(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
    char bf_dest[512]="", *msg;
    const char *target;
    void *free_arg=NULL;


    if (data==NULL || (strlen(data) < 3)) goto notice_error;
    if (!cmd_get_params(data, &free_arg, 1, &target)) goto notice_error;

    msg = strchr(data, ' ');
    if (IsNULLorEmpty(target) || IsNULLorEmpty(msg)) goto notice_error;

    msg++; // point to the notice message


    // generally refuse a notice size of more than 512 byte, as everything above will never arrive complete anyway
    if (strlen(msg) >= 512) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /notice+ \002error\002: message argument exceeds buffer size!");
        goto notice_error;
    }

    if (FiSH_encrypt(server, msg, target, bf_dest, sizeof(bf_dest))==0) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /notice+ \002error\002: Encryption disabled or no key found for %s.", target);
        goto notice_error;
    }

    irc_send_cmdv((IRC_SERVER_REC *)server, "NOTICE %s :%s\n", target, bf_dest);

    signal_emit("message irc own_notice", 3, server, msg, target);
    cmd_params_free(free_arg);
    return;

notice_error:
    if (free_arg) cmd_params_free(free_arg);
    printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
              "\002FiSH:\002 Usage: /notice+ <nick/#channel> <notice message>");
}

/*
 * New command: /me+ <action message>
 */
void cmd_crypt_action(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{	// New command: /me+ <action message>
    char bf_dest[512] = { '\0' };
    const char *target;


    if (data==NULL || (strlen(data) < 2)) goto action_error;

    if (item!=NULL) target=window_item_get_target(item);
    else goto action_error;


    // generally refuse an action size of more than 512 byte, as everything above will never arrive complete anyway
    if (strlen(data) >= 512) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /me+ \002error\002: message argument exceeds buffer size!");
        return;
    }

    if (FiSH_encrypt(server, (char *)data, target, bf_dest, sizeof(bf_dest))==0) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /me+ \002error\002: Encryption disabled or no key found for %s.", target);
        return;
    }

    irc_send_cmdv((IRC_SERVER_REC *)server, "PRIVMSG %s :\001ACTION %s\001\n", target, bf_dest);

    signal_emit("message irc own_action", 3, server, data, target);
    return;

action_error:
    printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
              "\002FiSH:\002 Usage: /me+ <action message>");
}

/*
 * Set encrypted topic for current channel, irssi syntax: /topic+ <your topic>
 */
void cmd_crypt_topic(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
    char bf_dest[512]="";
    const char *target;


    if (data==0 || *data=='\0') goto topic_error;
    if (item!=NULL) target=window_item_get_target(item);
    else goto topic_error;


    if (!ischannel(*target)) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 Please change to the channel window where you want to set the topic!");
        goto topic_error;
    }

    // generally refuse a topic size of more than 512 byte, as everything above will never arrive complete anyway
    if (strlen(data) >= 512) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /topic+ error: topic length exceeds buffer size!");
        goto topic_error;
    }

    // encrypt a message (using key for target)
    if (FiSH_encrypt(server, data, target, bf_dest, sizeof(bf_dest))==0) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 /topic+ error: Encryption disabled or no key found for %s.", target);
        goto topic_error;
    }

    irc_send_cmdv((IRC_SERVER_REC *)server, "TOPIC %s :%s\n", target, bf_dest);
    return;

topic_error:
    printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
              "\002FiSH:\002 Usage: /topic+ <your new topic>");
}

void cmd_helpfish(const char *arg, SERVER_REC *server, WI_ITEM_REC *item)
{
    printtext(NULL, NULL, MSGLEVEL_CRAP,
              "\n\002FiSH HELP:\002 For more information read FiSH-irssi.txt :)\n\n"
              " /topic+ <your new topic>\n"
              " /notice+ <nick/#channel> <notice message>\n"
              " /me+ <your action message>\n"
              " /setkey [-<server tag>] [<nick | #channel>] <key>\n"
              " /delkey [-<server tag>] [<nick | #channel>]\n"
              " /key [-<server tag>] [<nick | #channel>]\n"
              " /keyx [<nick>] (DH1080 KeyXchange)\n"
              " /setinipw <sekure_blow.ini_password>\n"
              " /unsetinipw\n");
}


void cmd_setinipw(const char *iniPW, SERVER_REC *server, WI_ITEM_REC *item)
{
    int pw_len, re_enc=0;
    char clean_key[KEYBUF_SIZE];

    if (iniPW != NULL) {
        pw_len=strlen(iniPW);
        if (pw_len < 1 || (size_t)pw_len > sizeof(clean_key)) {
            printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                      "\002FiSH:\002 No parameters. Usage: /setinipw <sekure_blow.ini_password>");
            return;
        }

        if (strfcpy(clean_key, iniPW, sizeof(clean_key)) == NULL) return;
        pw_len = strlen(clean_key);

        if (pw_len < 8) {
            printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                      "\002FiSH:\002 Password too short, at least 8 characters needed! Usage: /setinipw <sekure_blow.ini_password>");
            return;
        }
    }

    re_enc = fish2_rekey(fish2_ctx, clean_key);
    if (re_enc < 0) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                  "\002FiSH ERROR:\002 Unable to write new blow.ini, probably out of disc space.");
        return;
    }

    if (re_enc) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL,
                  MSGLEVEL_CRAP, "\002FiSH: Re-encrypted blow.ini\002 with new password.");
    }

    if (iniPW != NULL) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL,
                  MSGLEVEL_CRAP, "\002FiSH:\002 blow.ini password hash saved.");
    }
}

/*
 * Change back to default blow.ini password, irssi syntax: /unsetinipw
 */
static void cmd_unsetinipw(const char *arg, SERVER_REC *server, WI_ITEM_REC *item)
{
    int recrypted = fish2_rekey(fish2_ctx, NULL);

    if (recrypted < 0) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                  "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
        return;
    }

    printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
              "\002FiSH:\002 Changed back to default blow.ini password, you won't have to enter it on start-up anymore!");
}

/**
 * Sets the key for a nick / channel in a server
 * @param data command
 * @param server irssi server record
 * @param item irssi window/item
 */
void cmd_setkey(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
    GHashTable *optlist;
    const char *target, *key;
    void *free_arg;

    const char* target_window = (item ? window_item_get_target(item) : NULL);

    printtext(server, target_window, MSGLEVEL_CRAP, "\002FiSH\002: Setting key");

    if (IsNULLorEmpty(data)) {
        printtext(server, target_window, MSGLEVEL_CRAP,
                  "\002FiSH:\002 No parameters. Usage: /setkey [-<server tag>] [<nick | #channel>] <key>");
        return;
    }

    if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
                        PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
                        "setkey", &optlist, &target, &key))
        return;

    if (*target=='\0') {
        printtext(server, target_window, MSGLEVEL_CRAP,
                  "\002FiSH:\002 No parameters. Usage: /setkey [-<server tag>] [<nick | #channel>] <key>");
        cmd_params_free(free_arg);
        return;
    }

    printtext(server, target_window, MSGLEVEL_CRAP, "\002FiSH\002: Params valid.");

    server = cmd_options_get_server("setkey", optlist, server);
    if (server == NULL || !server->connected)
        cmd_param_error(CMDERR_NOT_CONNECTED);

    if (*key=='\0') {
        // one paramter given - it's the key
        key = target;
        if (item != NULL) target = window_item_get_target(item);
        else {
            printtext(NULL, NULL, MSGLEVEL_CRAP,
                      "\002FiSH:\002 Please define nick/#channel. Usage: /setkey [-<server tag>] [<nick | #channel>] <key>");
            cmd_params_free(free_arg);
            return;
        }
    }

    if (fish2_set_key(fish2_ctx, server_tag(server), target, key) < 0) {
        printtext(server, target_window, MSGLEVEL_CRAP,
                  "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
        cmd_params_free(free_arg);
        return;
    }

    printtext(server, target_window, MSGLEVEL_CRAP,
              "\002FiSH:\002 Key for %s@%s successfully set!", target, server->tag);

    cmd_params_free(free_arg);
}

void cmd_delkey(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
    GHashTable *optlist;
    char *target;
    void *free_arg;

    if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
                        PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
                        "delkey", &optlist, &target))
        return;

    if (item != NULL && IsNULLorEmpty(target) ) target = (char *) window_item_get_target(item);

    if (IsNULLorEmpty(target)) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                  "\002FiSH:\002 No parameters. Usage: /delkey [-<server tag>] [<nick | #channel>]");
        return;
    }

    server = cmd_options_get_server("delkey", optlist, server);
    if (server == NULL || !server->connected)
        cmd_param_error(CMDERR_NOT_CONNECTED);

    target = (char *)g_strchomp(target);

    if (fish2_unset_key(fish2_ctx, server_tag(server), target) < 0) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                  "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
        return;
    }

    printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
              "\002FiSH:\002 Key for %s@%s successfully removed!", target, server->tag);
}

void cmd_key(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
    GHashTable *optlist;
    char *target;
    char theKey[KEYBUF_SIZE]="";
    void *free_arg;

    if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
                        PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
                        "key", &optlist, &target))
        return;

    if (item != NULL && IsNULLorEmpty(target) ) target = (char *) window_item_get_target(item);

    if (IsNULLorEmpty(target)) {
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                  "\002FiSH:\002 Please define nick/#channel. Usage: /key [-<server tag>] [<nick | #channel>]");
        return;
    }

    server = cmd_options_get_server("key", optlist, server);
    if (server == NULL || !server->connected)
        cmd_param_error(CMDERR_NOT_CONNECTED);

    target = (char *)g_strchomp(target);

    if (fish2_get_key(fish2_ctx, server_tag(server), target, theKey) < 0) {
        ZeroMemory(theKey, KEYBUF_SIZE);
        printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
                  "\002FiSH:\002 Key for %s@%s not found or invalid!", target, server->tag);
        return;
    }

    printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 Key for %s@%s: %s", target, server->tag, theKey);
    ZeroMemory(theKey, KEYBUF_SIZE);
}

void cmd_keyx(const char *target, SERVER_REC *server, WI_ITEM_REC *item)
{
    if (IsNULLorEmpty(target)) {
        if (item!=NULL) target = window_item_get_target(item);
        else {
            printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Please define nick/#channel. Usage: /keyx <nick/#channel>");
            return;
        }
    }

    if (ischannel(*target)) {
        printtext(server, target, MSGLEVEL_CRAP, "\002FiSH:\002 KeyXchange does not work for channels!");
        return;
    }

    keyx_start(keyx_ctx);

    irc_send_cmdv(
        (IRC_SERVER_REC *)server,
        "NOTICE %s :%s %s",
        target,
        "DH1080_INIT",
        keyx_public_key(keyx_ctx));

    printtext(server, item!=NULL ? window_item_get_target(item) : NULL, MSGLEVEL_CRAP,
              "\002FiSH:\002 Sent my DH1080 public key to %s, waiting for reply ...", target);
}

void DH1080_received(SERVER_REC *server, char *msg, char *nick, char *address, char *target)
{
    char their_public_key[180+1] = { '\0' };
    char secret_key[180+1] = { '\0' };

    if (ischannel(*target) || ischannel(*nick)) return; // no KeyXchange for channels...

    if (strncmp(msg, "DH1080_INIT ", 12) == 0) {
        strncpy(their_public_key, msg+12, 180);

        if (query_find(server, nick) == NULL) { // query window not found, lets create one
            keyx_query_created=1;
            irc_query_create(server->tag, nick, TRUE);
            keyx_query_created=0;
        }

        printtext(server, nick, MSGLEVEL_CRAP, "\002FiSH:\002 Received DH1080 public key from %s, sending mine...", nick);

        keyx_start(keyx_ctx);
        irc_send_cmdv(
            (IRC_SERVER_REC *)server,
            "NOTICE %s :%s %s",
            nick,
            "DH1080_FINISH",
            keyx_public_key(keyx_ctx));

    } else if (strncmp(msg, "DH1080_FINISH ", 14) == 0) {
        strncpy(their_public_key, msg+14, 180);
    } else {
        return;
    }

    if (keyx_finish(keyx_ctx, their_public_key, secret_key, 180+1) < 0) {
      return;
    }

    signal_stop();

    if (fish2_set_key(fish2_ctx, server_tag(server), nick, secret_key) < 0) {
        ZeroMemory(their_public_key, sizeof(their_public_key));
        ZeroMemory(secret_key, sizeof(secret_key));
        printtext(server, nick, MSGLEVEL_CRAP, "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
        return;
    }

    ZeroMemory(their_public_key, sizeof(their_public_key));
    ZeroMemory(secret_key, sizeof(secret_key));

    printtext(server, nick, MSGLEVEL_CRAP, "\002FiSH:\002 Key for %s successfully set!", nick);
}

/*
 * Perform auto-keyXchange only for known people
 */
void do_auto_keyx(QUERY_REC *query, int automatic)
{
    if (keyx_query_created)
        return; // query was created by FiSH.

    if (!fish2_get_setting_bool(fish2_ctx, FISH2_AUTO_KEYEXCHANGE))
        return;

    if (!fish2_has_key(fish2_ctx, query->server->tag, query->name)) {
        cmd_keyx(query->name, query->server, NULL);
    }
}

/*
 * Copy key for old nick to use with the new one
 */
void query_nick_changed(QUERY_REC *query, char *orignick)
{
    char theKey[KEYBUF_SIZE] = { '\0' };

    if (fish2_get_setting_bool(fish2_ctx, FISH2_NICKTRACKER)) return;

    if (orignick==NULL || strcasecmp(orignick, query->name)==0) return;	// same nick, different case?

    if (fish2_get_key(fish2_ctx, server_tag(query->server), orignick, theKey) < 0)
        return; // see if there is a key for the old nick

    if (fish2_set_key(fish2_ctx, server_tag(query->server), query->name, theKey) < 0) {
        printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH ERROR:\002 Unable to write to blow.ini, probably out of space or permission denied.");
    }

    ZeroMemory(theKey, KEYBUF_SIZE);
}

void prompt_for_password (char* a_output)
{
    char* password = getpass(" --> Please enter your blow.ini password: ");

    strcpy(a_output, password);
    ZeroMemory(password, strlen(password));
    irssi_redraw(); // getpass() screws irssi GUI, lets redraw!
}

static int get_random_seed (char seed[])
{
    static const unsigned int seed_length = 256;

    // don't use /dev/random, it's a blocking device
    FILE *hRnd = fopen("/dev/urandom", "rb");

    if (!hRnd) return FALSE;

    if (fread(seed, 1, seed_length, hRnd) != seed_length) {
        fclose(hRnd);
        return FALSE;
    }

    fclose(hRnd);
    return TRUE;
}

int key_exchange_init (const char* ini_path)
{
    char seed[256];

    if (get_random_seed(seed) == FALSE) return FALSE;

    if (keyx_init(&keyx_ctx, seed) < 0) return FALSE;

    memset(seed, 0, sizeof(seed));
    return TRUE;
}

void fish_init(void)
{
    static const char blow_ini[]="blow.ini";
    char iniPath[256];
    snprintf(iniPath, sizeof(iniPath), "%s/%s", get_irssi_dir(), blow_ini);

    if (key_exchange_init(iniPath) == FALSE) return;

    if (fish2_init(&fish2_ctx, iniPath) < 0) return;

    if (fish2_has_master_key(fish2_ctx)) {
        char iniKey[100];
        prompt_for_password(iniKey);

        if (fish2_validate_master_key(fish2_ctx, iniKey)) {
            printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Wrong blow.ini password entered, try again...");
            printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH module NOT loaded.\002");
            return;
        }
        printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Correct blow.ini password entered, lets go!");

    } else {
        fish2_validate_master_key(fish2_ctx, NULL);

        printtext(NULL, NULL, MSGLEVEL_CRAP, "\002FiSH:\002 Using default password to decrypt blow.ini... Try /setinipw to set a custom password.");
    }


    signal_add_first("server sendmsg", (SIGNAL_FUNC) encrypt_msg);
    signal_add_first("message private", (SIGNAL_FUNC) decrypt_msg);
    signal_add_first("message public", (SIGNAL_FUNC) decrypt_msg);
    signal_add_first("message irc notice", (SIGNAL_FUNC) decrypt_notice);
    signal_add_first("message irc action", (SIGNAL_FUNC) decrypt_action);

    signal_add_first("message own_private", (SIGNAL_FUNC) format_msg);
    signal_add_first("message own_public", (SIGNAL_FUNC) format_msg);

    signal_add_first("channel topic changed", (SIGNAL_FUNC) decrypt_changed_topic);
    signal_add_first("message topic", (SIGNAL_FUNC) decrypt_topic);
    signal_add_first("server incoming", (SIGNAL_FUNC) raw_handler);

    signal_add("query created", (SIGNAL_FUNC) do_auto_keyx);
    signal_add("query nick changed", (SIGNAL_FUNC) query_nick_changed);

    command_bind("topic+", NULL, (SIGNAL_FUNC) cmd_crypt_topic);
    command_bind("notice+", NULL, (SIGNAL_FUNC) cmd_crypt_notice);
    command_bind("notfish", NULL, (SIGNAL_FUNC) cmd_crypt_notice);
    command_bind("me+", NULL, (SIGNAL_FUNC) cmd_crypt_action);
    command_bind("setkey", NULL, (SIGNAL_FUNC) cmd_setkey);
    command_bind("delkey", NULL, (SIGNAL_FUNC) cmd_delkey);
    command_bind("key", NULL, (SIGNAL_FUNC) cmd_key);
    command_bind("showkey", NULL, (SIGNAL_FUNC) cmd_key);
    command_bind("keyx", NULL, (SIGNAL_FUNC) cmd_keyx);
    command_bind("setinipw", NULL, (SIGNAL_FUNC) cmd_setinipw);
    command_bind("unsetinipw", NULL, (SIGNAL_FUNC) cmd_unsetinipw);

    command_bind("fishhelp", NULL, (SIGNAL_FUNC) cmd_helpfish);
    command_bind("helpfish", NULL, (SIGNAL_FUNC) cmd_helpfish);

    printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
              "FiSH v1.00 - encryption module for irssi loaded! URL: https://github.com/falsovsky/FiSH-irssi\n"
              "Try /helpfish or /fishhelp for a short command overview");

    module_register("fish", "core");
}

void fish_deinit(void)
{
    signal_remove("server sendmsg", (SIGNAL_FUNC) encrypt_msg);
    signal_remove("message private", (SIGNAL_FUNC) decrypt_msg);
    signal_remove("message public", (SIGNAL_FUNC) decrypt_msg);
    signal_remove("message irc notice", (SIGNAL_FUNC) decrypt_notice);
    signal_remove("message irc action", (SIGNAL_FUNC) decrypt_action);

    signal_remove("message own_private", (SIGNAL_FUNC) format_msg);
    signal_remove("message own_public", (SIGNAL_FUNC) format_msg);

    signal_remove("channel topic changed", (SIGNAL_FUNC) decrypt_changed_topic);
    signal_remove("message topic", (SIGNAL_FUNC) decrypt_topic);
    signal_remove("server incoming", (SIGNAL_FUNC) raw_handler);

    signal_remove("query created", (SIGNAL_FUNC) do_auto_keyx);
    signal_remove("query nick changed", (SIGNAL_FUNC) query_nick_changed);

    command_unbind("topic+", (SIGNAL_FUNC) cmd_crypt_topic);
    command_unbind("notice+", (SIGNAL_FUNC) cmd_crypt_notice);
    command_unbind("notfish", (SIGNAL_FUNC) cmd_crypt_notice);
    command_unbind("me+", (SIGNAL_FUNC) cmd_crypt_action);
    command_unbind("setkey", (SIGNAL_FUNC) cmd_setkey);
    command_unbind("delkey", (SIGNAL_FUNC) cmd_delkey);
    command_unbind("key", (SIGNAL_FUNC) cmd_key);
    command_unbind("showkey", (SIGNAL_FUNC) cmd_key);
    command_unbind("keyx", (SIGNAL_FUNC) cmd_keyx);
    command_unbind("setinipw", (SIGNAL_FUNC) cmd_setinipw);
    command_unbind("unsetinipw", (SIGNAL_FUNC) cmd_unsetinipw);

    command_unbind("fishhelp", (SIGNAL_FUNC) cmd_helpfish);
    command_unbind("helpfish", (SIGNAL_FUNC) cmd_helpfish);

    keyx_deinit(keyx_ctx);
}

/*
 * Removes leading and trailing blanks from string
 * @param dest destination buffer
 * @param buffer string to clean
 * @param destSize size of destination buffer
 * @return destination buffer
 */
char *strfcpy(char *dest, const char* buffer, int destSize)
{
    int i = 0;
    int k = strlen(buffer);

    if (k < 2) return NULL;

    while (buffer[i]==' ') i++;
    while (buffer[k-1]==' ') k--;

    snprintf(dest, destSize, "%*s", k - i, buffer + i);
    return dest;
}
