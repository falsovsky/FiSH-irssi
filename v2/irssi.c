#define MODULE_NAME "fish2"
#include <irssi-config.h>

#include <common.h>
#include <core/signals.h>
#include <core/servers.h>
#include <core/channels.h>
#include <core/queries.h>
#include <core/levels.h>
#include <core/commands.h>
#include <fe-common/core/printtext.h>
#include <irc/core/irc.h>

#include "fish.h"

static const char* fish_who(SERVER_REC *server, char *target, char *nick) {
  if (server_ischannel(server, target))
    return target;
  else
    return nick;
}

static char *fish_first_word(const char* msg) {
  char *word = strdup(msg);

  char* first_space = strchr(word, ' ');
  if (first_space)
    *first_space = 0;

  return word;
}

void fish_send_message(SERVER_REC *server, char *target, char *msg, int target_type) {
  char *encrypted_msg = fish_encrypt(server->tag, target, msg);
  signal_continue(5, server, target, encrypted_msg, target_type);
  free(encrypted_msg);
}

void fish_recv_message(SERVER_REC *server, char *msg, char *nick, char *address, char *target) {
  const char *who = fish_who(server, target, nick);

  char *decrypted_msg = fish_decrypt(server->tag, who, msg);
  signal_continue(5, server, decrypted_msg, nick, address, target);
  free(decrypted_msg);
}

void fish_recv_notice(SERVER_REC *server, char *msg, char *nick, char *address, char *target) {
  const char *who = fish_who(server, target, nick);

  if (strncmp(msg, "DH1080_", 7) == 0) {
    // handle dh
  } else {
    char *decrypted_msg = fish_decrypt(server->tag, who, msg);
    signal_continue(5, server, decrypted_msg, nick, address, target);
    free(decrypted_msg);
  }
}

void fish_recv_action(SERVER_REC *server, char *msg, char *nick, char *address, char *target) {
  const char *who = fish_who(server, target, nick);

  char *decrypted_msg = fish_decrypt(server->tag, who, msg);
  signal_continue(5, server, decrypted_msg, nick, address, target);
  free(decrypted_msg);
}

void fish_recv_topic_change(CHANNEL_REC * chan_rec) {
  char *old_topic = chan_rec->topic;

  chan_rec->topic = fish_decrypt(chan_rec->server->tag, chan_rec->name, chan_rec->topic);
  signal_continue(1, chan_rec);
  free(chan_rec->topic);

  chan_rec->topic = old_topic;
}

void fish_recv_topic(SERVER_REC *server, char *channel, char *topic, char *nick, char *address) {
  char *decrypted_msg = fish_decrypt(server->tag, channel, topic);
  signal_continue(5, server, channel, decrypted_msg, nick, address);
  free(decrypted_msg);
}

void fish_recv_raw_topic(SERVER_REC *server, char *data) {
  char *channel = fish_first_word(data + 4);
  char *topic = data + 4 + strlen(channel) + 2;
  if (data + strlen(data) < topic) {
    free(channel);
    return;
  }

  char *decrypted_msg = fish_decrypt(server->tag, channel, topic);
  signal_continue(2, server, decrypted_msg);
  free(decrypted_msg);
  free(channel);
}

void fish_recv_raw(SERVER_REC *server, char *data) {
  if (strncmp("332 ", data, 4) == 0) {
    fish_recv_raw_topic(server, data);
  }
}

void fish_recv_query_nick_change(QUERY_REC* query, char *orignick) {
  fish_copy_key(query->server->tag, orignick, query->server->tag, query->name);
}

void fish_cmd_topic(const char *data, SERVER_REC *server, WI_ITEM_REC *item) {
  const char* channel = window_item_get_target(item);

  if (!*data) {
    printtext(server, channel, MSGLEVEL_CRAP, "\002FiSH:\002 /topic+ error: you must specify a topic");
    return;
  }

  char *encrypted_msg = fish_encrypt(server->tag, channel, data);
  irc_send_cmdv((IRC_SERVER_REC*)server, "TOPIC %s :%s\n", channel, encrypted_msg);
  free(encrypted_msg);
}

void fish_cmd_notice(const char *data, SERVER_REC *server, WI_ITEM_REC *item) {
  const char *target, *msg;
  void *free_arg;

  if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTCHAN | PARAM_FLAG_GETREST, item, &target, &msg)) {
    return;
  }

  char *encrypted_msg = fish_encrypt(server->tag, target, msg);
	irc_send_cmdv((IRC_SERVER_REC*)server, "NOTICE %s :%s\n", target, encrypted_msg);
  free(encrypted_msg);

  free(free_arg);
}

void fish_cmd_me(const char *data, SERVER_REC *server, WI_ITEM_REC *item) {
  const char *target = window_item_get_target(item);

  char *encrypted_msg = fish_encrypt(server->tag, target, data);
	irc_send_cmdv((IRC_SERVER_REC*)server, "PRIVMSG %s :\001ACTION %s\001\n", target, encrypted_msg);
  free(encrypted_msg);
}


typedef struct {
  int type;
  const char* name;
  SIGNAL_FUNC func;
} fish_signal_t;

fish_signal_t signals[] = {
// Encryption/decryption
  { 0, "server sendmsg", (SIGNAL_FUNC)fish_send_message },
  { 0, "message private", (SIGNAL_FUNC)fish_recv_message },
  { 0, "message public", (SIGNAL_FUNC)fish_recv_message },
  { 0, "message irc notice", (SIGNAL_FUNC)fish_recv_notice },
  { 0, "message irc action", (SIGNAL_FUNC)fish_recv_action },
  { 0, "channel topic changed", (SIGNAL_FUNC)fish_recv_topic_change },
  { 0, "message topic", (SIGNAL_FUNC) fish_recv_topic },
  { 0, "server incoming", (SIGNAL_FUNC)fish_recv_raw },
//  { 1, "complete command topic+", (SIGNAL_FUNC)sig_complete_topic_plus },
  { 2, "topic+", (SIGNAL_FUNC) fish_cmd_topic },
  { 2, "notice+", (SIGNAL_FUNC) fish_cmd_notice },
  { 2, "me+", (SIGNAL_FUNC) fish_cmd_me },

//  Diffie-Hellman exchange
//  { 1, "query created", (SIGNAL_FUNC)do_auto_keyx },
//  { 2, "keyx", (SIGNAL_FUNC) cmd_keyx);

// Key management
  { 1, "query nick changed", (SIGNAL_FUNC)fish_recv_query_nick_change },
//  { 2, "setkey", (SIGNAL_FUNC) cmd_setkey);
//  { 2, "delkey", (SIGNAL_FUNC) cmd_delkey);
//  { 2, "key", (SIGNAL_FUNC) cmd_key);
//  { 2, "showkey", (SIGNAL_FUNC) cmd_key);
//  { 2, "setinipw", (SIGNAL_FUNC) cmd_setinipw);
//  { 2, "unsetinipw", (SIGNAL_FUNC) cmd_unsetinipw);
};

void fish_init() {
  int i;
  for (i = 0; i < sizeof(signals)/sizeof(fish_signal_t); i++) {
    switch (signals[i].type) {
      case 0:
        signal_add_first(signals[i].name, signals[i].func);
        break;
      case 1:
        signal_add(signals[i].name, signals[i].func);
        break;
      case 2:
        command_bind(signals[i].name, NULL, signals[i].func);
        break;
    }
  }

  // TODO: add settings

  module_register("fish", "core");
}

void fish_deinit() {
  int i;
  for (i = 0; i < sizeof(signals)/sizeof(fish_signal_t); i++) {
    switch (signals[i].type) {
      case 0:
      case 1:
        signal_remove(signals[i].name, signals[i].func);
        break;
      case 2:
	      command_unbind(signals[i].name, signals[i].func);
        break;
    }
  }
}
