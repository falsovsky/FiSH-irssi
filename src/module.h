#define MODULE_NAME "fish"

#include <irssi-config.h>

#include <common.h>
#include <core/settings.h>
#include <core/levels.h>
#include <core/signals.h>
#include <core/recode.h>
#include <irc/core/irc.h>
#include <irc/core/irc-servers.h>
#include <irc/core/irc-queries.h>
#include <fe-common/core/printtext.h>
#include <fe-common/core/keyboard.h>

#ifdef ischannel
    #undef ischannel
#endif
