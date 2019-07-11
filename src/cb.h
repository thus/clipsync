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

#ifndef __CB_H__
#define __CB_H__

#include <inttypes.h>
#include <time.h>

#include <libclipboard.h>

/**
 * Structure containing clipboard state.
 */
typedef struct {
    char *sync_file;               /**< File used to synchronize clipboard */
    char *sync_file_tmp;           /**< Template for making temporary files */
    int mode;                      /**< Determine which clipboard is used */
    struct timespec last_modified; /**< The last modified time of sync file */
    uint32_t hash[4];              /**< Hash of last clipboard content */
    clipboard_c *clipboard;        /**< The clipboard to interact with */
    unsigned char *key;            /**< Key used to encrypt/decrypt clipboard */
} CBState;

/* Function prototypes */
CBState *cb_create(const char *, const char *, int, clipboard_c *,
		   unsigned char *);
void cb_destroy(CBState *);
int cb_sync(CBState *);
int cb_sync_file_write(const char *, CBState *);
char *cb_sync_file_read(CBState *);

#endif /* __CB_H__ */

