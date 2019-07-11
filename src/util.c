/* Copyright (C) 2019 Mats Klepsland
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "util.h"

#define LOG_MESSAGE_MAX_LEN 1024
#define LOG_MESSAGE_TIMESTAMP_LEN 20

/**
 * Structure representing a simple lookup table.
 */
typedef struct {
    const char *name;
    const int value;
} LookupTable;

/**
 * Lookup table containing log levels.
 */
LookupTable log_levels[] = {
    { "debug",   LOG_LEVEL_DEBUG },
    { "info",    LOG_LEVEL_INFO },
    { "notice",  LOG_LEVEL_NOTICE },
    { "warning", LOG_LEVEL_WARNING },
    { "error",   LOG_LEVEL_ERROR },
    { NULL,      0 }
};

/**
 * \brief Lookup log level based on string.
 *
 * \param name Log level as string.
 *
 * \retval level Log level as integer.
 * \retval -1 on unknown log level.
 */
int log_level_lookup(const char *name)
{
    for (LookupTable *p = log_levels; p->name != NULL; p++)
    {
        if (strcmp(p->name, name) == 0)
            return p->value;
    }

    return -1;
}

/**
 * \brief Log message if log level is high enough.
 *
 * \param log_level The log level used.
 * \param format    Format string.
 * \param ...       Variable arguments.
 */
void log_msg(int log_level, const char *format, ...)
{
    if (log_level < g_log_level)
        return;

    char buffer[LOG_MESSAGE_MAX_LEN];

    time_t ltime = time(NULL);
    struct tm result;
    char stime[LOG_MESSAGE_TIMESTAMP_LEN];

    localtime_r(&ltime, &result);
    strftime(stime, sizeof(stime), "%FT%H:%M:%S", &result);

    va_list args;
    va_start(args, format);

    vsnprintf(buffer, sizeof(buffer), format, args);    
    printf("%s -- %s", stime, buffer);

    va_end(args);
}

/**
 * \brief Handle signals.
 *
 * \param signal The signal to handle.
 */
void signal_handler(int signal)
{
    switch (signal)
    {
        case SIGINT:
            /* Fall through */
        case SIGTERM:
            /* Fall through */
        case SIGQUIT:
            g_sig_flags = SIGNAL_STOP;
	    break;
    }
}

/**
 * \brief Signal application failure.
 */
void signal_failure(void)
{
    g_sig_flags |= SIGNAL_FAILURE;
}

