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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdarg.h>
#include <signal.h>

/* Global log level */
extern int g_log_level;

extern sig_atomic_t g_sig_flags;

/* Signals */
#define SIGNAL_STOP    0x01
#define SIGNAL_FAILURE 0x02

/* Logging macros */
#define log_debug(...) \
        do { log_msg(LOG_LEVEL_DEBUG, "%s:%d:%s(): ",__FILE__,\
			  __LINE__, __func__);\
             log_msg(LOG_LEVEL_DEBUG, __VA_ARGS__); } while (0)
#define log_info(...) \
        do { log_msg(LOG_LEVEL_INFO, __VA_ARGS__); } while (0)
#define log_notice(...) \
        do { log_msg(LOG_LEVEL_NOTICE, __VA_ARGS__); } while (0)
#define log_warning(...) \
        do { log_msg(LOG_LEVEL_WARNING, __VA_ARGS__); } while (0)
#define log_error(...) \
        do { log_msg(LOG_LEVEL_ERROR, __VA_ARGS__); } while (0)

/* Log levels */
enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_NOTICE,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR
};

/* Function prototypes */
int log_level_lookup(const char *);
void log_msg(int, const char *, ...);
void signal_handler(int);
void signal_failure(void);

#endif /* __UTIL_H__ */

