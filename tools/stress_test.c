/**
 * Stress test clipsync sync file read and write functions to try to
 * detect file system race conditiions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>

#include <libclipboard.h>
#include <sodium.h>

#include "../src/cb.h"

#define STRESS_DEFAULT_DURATION 60
#define STRESS_DEFAULT_WAIT 50
#define STRESS_DEFAULT_NUM_THREADS 5

int g_log_level = 0;
sig_atomic_t g_sig_flags = 0;

static const char *DEFAULT_SYNC_DIR = "/tmp";

int verbose = 0;
int duration = STRESS_DEFAULT_DURATION;
int wait = STRESS_DEFAULT_WAIT;  /* in ms */

static void print_usage(const char *prog)
{
    printf("USAGE: %s\n"
           "Stress test clipsync.\n\n"
	   "OPTIONS:\n"
	   "\t-d <dir>     : synchronize using this directory\n"
	   "\t-s <seconds> : duration to run the stress test\n"
	   "\t-w <ms>      : wait time between runs\n"
	   "\t-t <threads> : number of threads to use\n"
           "\t-v           : verbose output\n"
	   "\t-h           : print this help\n\n",
	   prog);
}

static void gen_rand_str(char *s, const int length)
{
    static const char charset[] = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCD"
	                          "EFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghi"
				  "jklmnopqrstuvvwxyz{|}~";

    for (int i = 0; i < length; ++i)
    {
        s[i] = charset[rand() % (sizeof(charset) - 1)];
    }

    s[length] = '\0';
}

static void *stress_test_thread(void *user)
{
    CBState *cb = (CBState *)user;

    time_t now = time(NULL);
    time_t end = now + duration;

    while (1)
    {
        now = time(NULL);
	if (now >= end)
            break;

        char *data = cb_sync_file_read(cb);
        if (data == NULL) {
            fprintf(stderr, "Error reading from sync file\n");
	    exit(EXIT_FAILURE);
        }

	if (verbose) {
	    printf("Read %ld bytes of data from %s\n", strlen(data),
                   cb->sync_file);
	}

	free(data);

        int length = rand() % 100000;
        char randstr[length];
	gen_rand_str(randstr, length);

        int rv = cb_sync_file_write(randstr, cb);
        if (rv != 0) {
            fprintf(stderr, "Error writing to sync file\n");
	    exit(EXIT_FAILURE);
        }

        if (verbose) {
            printf("Written %d bytes of data to %s\n", length, cb->sync_file);
	}

        struct timespec sleep = {wait / 1000, wait % 1000 * 1000000L};
	nanosleep(&sleep, NULL);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    char *sync_dir = NULL;
    int num_threads = STRESS_DEFAULT_NUM_THREADS;

    int c;
    char *opts = "d:s:t:w:vh";
    while ((c = getopt(argc, argv, opts)) != -1)
    {
        switch (c)
        {
            case 'd':
                sync_dir = strdup(optarg);
		break;
            case 's':
		duration = atoi(optarg);
		break;
            case 't':
		num_threads = atoi(optarg);
		break;
            case 'w':
		wait = atoi(optarg);
		break;
            case 'v':
		verbose = 1;
		break;
            case 'h':
                print_usage(argv[0]);
		exit(EXIT_SUCCESS);
            default:
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
    }

    if (sync_dir == NULL) {
        sync_dir = strdup(DEFAULT_SYNC_DIR);
    }

    if (sodium_init() == -1) {
        fprintf(stderr, "Error initializing sodium library\n");
	exit(EXIT_FAILURE);
    }

    srand(time(NULL));

    clipboard_c *clipboard = clipboard_new(NULL);
    if (clipboard == NULL) {
        fprintf(stderr, "Clipboard initialization failed\n");
	exit(EXIT_FAILURE);
    }

    CBState *cb = cb_create(".cs_stress_test", sync_dir,
		            LCB_SELECTION, clipboard,
			    (unsigned char *)"ABCDEFGH");
    if (cb == NULL) {
        fprintf(stderr, "Error creating clipboard state\n");
	exit(EXIT_FAILURE);
    }

    /* Make sure the sync file exists before the threads start, so we
       don't have to check for its existence every time. */
    int rv = cb_sync_file_write("ABCDEFGHIJKLMNOPQRSTUVWXYZ", cb);
    if (rv != 0) {
        fprintf(stderr, "Error writing to sync file\n");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++)
    {
        if (pthread_create(&threads[i], NULL, stress_test_thread, cb)) {
            fprintf(stderr, "Error creating threads\n");
            exit(EXIT_FAILURE);
	}
    }

    for (int i = 0; i < num_threads; i++)
    {
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Error joining threads\n");
	    exit(EXIT_FAILURE);
	}
    }

    free(sync_dir);
    clipboard_free(clipboard);
    cb_destroy(cb);

    return EXIT_SUCCESS;
}

