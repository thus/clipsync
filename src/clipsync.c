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
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>

#include <libclipboard.h>
#include <sodium.h>

#include "cb.h"
#include "util.h"

#define MAX_CLIPBOARDS 2

int g_log_level = LOG_LEVEL_NOTICE;
sig_atomic_t g_sig_flags = 0;

static const char *CB_SYNC_FILE_MODE_CLIPBOARD = ".cs_clipboard";
static const char *CB_SYNC_FILE_MODE_SELECTION = ".cs_selection";

/**
 * \internal
 * \brief Print application usage.
 *
 * \param prog The name of the application.
 */
static void print_usage(const char *prog)
{
    printf("USAGE: %s\n"
           "Synchronize clipboards.\n\n"
	   "OPTIONS:\n"
	   "\t-d <dir>   : synchronize using this directory\n"
	   "\t-l <file>  : log output to this file\n"
	   "\t-L <level> : log level (debug/info/notice/warning/error)\n"
	   "\t-p <pw>    : password used to encrypt clipboard data\n"
	   "\t-h         : print this help\n\n",
	   prog);
}

/**
 * \internal
 * \brief Run loop that synchronize clipboards.
 *
 * \param clipboards Array containing clipboards.
 * \param num        Number of clipboards.
 */
static void run_loop(CBState *clipboards[], int num)
{
    while (1)
    {
        if (g_sig_flags & SIGNAL_STOP)
            break;

	for (int i = 0; i < num; i++)
	{
	    int r = cb_sync(clipboards[i]);
	    if (r == -1) {
                signal_failure();
		return;
	    }
	}

	struct timespec ts = {0, 100000000L};
        nanosleep(&ts, NULL);
    }
}

int main(int argc, char **argv)
{
    char *sync_dir = NULL;
    char *log_file = NULL;
    char *passwd = NULL;
    unsigned char *key = NULL;
    CBState *clipboards[MAX_CLIPBOARDS] = {0};
    clipboard_c *clipboard = NULL;

    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);

    int c;
    char *opts = "d:l:L:p:h";
    while ((c = getopt(argc, argv, opts)) != -1)
    {
        switch (c)
	{
	    case 'd':
		sync_dir = strdup(optarg);
	        break;
            case 'l':
		log_file = strdup(optarg);
		break;
            case 'L':
                g_log_level = log_level_lookup(optarg);
		if (g_log_level == -1) {
                    log_error("Error: unknown log level (-L): %s\n", optarg);
		    signal_failure();
		    goto cleanup;
		}
		break;
            case 'p':
                passwd = strdup(optarg);
                break;
	    case 'h':
		print_usage(argv[0]);
		goto cleanup;
	    default:
		print_usage(argv[0]);
		signal_failure();
		goto cleanup;
	}
    }

    if (log_file != NULL) {
        FILE *fp = freopen(log_file, "a", stdout);
	if (fp == NULL) {
            log_error("Error redirecting stdout to '%s': %s\n", log_file,
                      strerror(errno));
	    signal_failure();
	    goto cleanup;
	}
    }

    log_info("Starting clipsync\n");

    if (passwd == NULL) {
        char *sync_pw = getenv("SYNC_PASSWORD");
	if (sync_pw == NULL) {
            log_error("No encryption password (-p <pw>) specified. Exiting.\n");
	    signal_failure();
	    goto cleanup;
	}
	passwd = strdup(sync_pw);
    }

    if (sync_dir == NULL) {
        log_error("No synchronize directory (-d <dir>) specified. Exiting.\n");
	signal_failure();
	goto cleanup;
    }

    if (sodium_init() == -1) {
        log_error("Error initializing sodium library\n");
	signal_failure();
	goto cleanup;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    key = calloc(1, crypto_box_SEEDBYTES);
    if (key == NULL) {
        log_error("Error allocating memory for encryption key\n");
	signal_failure();
	goto cleanup;
    }

    randombytes_buf(salt, sizeof(salt));

    if (crypto_pwhash(key, crypto_box_SEEDBYTES, passwd, strlen(passwd), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
		      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        log_error("Error calculating encryption key: %s\n", strerror(errno));
	signal_failure();
	goto cleanup;
    }

    free(passwd);
    passwd = NULL;

    clipboard = clipboard_new(NULL);
    if (clipboard == NULL) {
        log_error("Clipboard initialization failed\n");
	signal_failure();
        goto cleanup;
    }

    clipboards[0] = cb_create(CB_SYNC_FILE_MODE_CLIPBOARD, sync_dir,
		              LCB_CLIPBOARD, clipboard, key);
    if (clipboards[0] == NULL) {
        log_error("Error creating clipboard state\n");
	signal_failure();
	goto cleanup;
    }

    clipboards[1] = cb_create(CB_SYNC_FILE_MODE_SELECTION, sync_dir,
		              LCB_SELECTION, clipboard, key);
    if (clipboards[1] == NULL) {
        log_error("Error creating clipboard state\n");
	signal_failure();
	goto cleanup;
    }

    run_loop(clipboards, MAX_CLIPBOARDS);

    log_info("Stopping clipsync\n");
cleanup:

    if (clipboard != NULL)
        clipboard_free(clipboard);

    if (sync_dir != NULL)
        free(sync_dir);

    if (log_file != NULL)
        free(log_file);

    if (passwd != NULL)
        free(passwd);

    if (key != NULL)
        free(key);

    for (int i = 0; i < MAX_CLIPBOARDS; i++)
    {
        cb_destroy(clipboards[i]);
    }

    if (g_sig_flags & SIGNAL_FAILURE)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

