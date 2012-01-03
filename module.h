#define HAVE_CONFIG_H

#define MODULE_NAME "fish"

#include <common.h>
#include <core/servers.h>
#include <core/settings.h>
#include <core/levels.h>
#include <core/signals.h>
#include <core/commands.h>
#include <core/queries.h>
#include <core/channels.h>
#include <core/recode.h>
#include <fe-common/core/printtext.h>
#include <fe-common/core/window-items.h>
#include <irc/core/irc.h>
#include <irc/core/irc-commands.h>
#include <irc/core/irc-servers.h>


void irssi_redraw(void);

QUERY_REC *irc_query_create(const char *server_tag, const char *nick, int automatic);
