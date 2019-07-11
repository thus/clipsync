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
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libclipboard.h>
#include <sodium.h>

#include "cb.h"
#include "murmur3.h"
#include "util.h"

/* Ignore reading sync file if it is larger than 100mb */
#define CLIPSYNC_SYNC_FILE_MAX_SIZE 104857600

/* Seed used by MurmurHash3 */
uint32_t global_seed = 2976579765;

/**
 * \brief Create clipboard state.
 *
 * \param filename  Filename of the sync file to use.
 * \param sync_dir  The directory that should contain sync files.
 * \param mode      Determine which clipboard is used.
 * \param clipboard The clipboard to interact with.
 * \param key       Key used to encrypt/decrypt clipboard data.
 *
 * \retval cb on success.
 * \retval NULL on failure.
 */
CBState *cb_create(const char *filename, const char *sync_dir, int mode,
		   clipboard_c *clipboard, unsigned char *key)
{
    if (filename == NULL || sync_dir == NULL || clipboard == NULL
            || key == NULL)
        return NULL;

    CBState *cb = calloc(1, sizeof(CBState));
    if (cb == NULL)
        return NULL;

    int r = clock_gettime(CLOCK_REALTIME, &cb->last_modified);
    if (r == -1) {
        log_error("Getting time with clock_gettime failed: %s\n",
                  strerror(errno));
	cb_destroy(cb);
	return NULL;
    }

    cb->mode = mode;
    cb->clipboard = clipboard;
    cb->key = key;

    char *data = clipboard_text_ex(cb->clipboard, NULL, cb->mode);
    if (data != NULL) {
        MurmurHash3_x86_128(data, strlen(data), global_seed, cb->hash);
        free(data);
    }

    int path_len = strlen(filename) + strlen(sync_dir) + 2;
    cb->sync_file = calloc(1, path_len);
    if (cb->sync_file == NULL) {
        cb_destroy(cb);
	return NULL;
    }

    r = snprintf(cb->sync_file, path_len, "%s/%s", sync_dir, filename);
    if (r != path_len - 1) {
        cb_destroy(cb);
	return NULL;
    }

    cb->sync_file_tmp = calloc(1, path_len + 7);
    if (cb->sync_file_tmp == NULL) {
        cb_destroy(cb);
	return NULL;
    }

    r = snprintf(cb->sync_file_tmp, path_len + 7, "%s.XXXXXX", cb->sync_file);
    if (r != path_len + 6) {
        cb_destroy(cb);
	return NULL;
    }

    return cb;
}

/**
 * \brief Destroy clipboard state.
 *
 * \param cb Pointer to the clipboard state.
 */
void cb_destroy(CBState *cb)
{
    if (cb == NULL)
        return;

    if (cb->sync_file != NULL)
        free(cb->sync_file);

    if (cb->sync_file_tmp != NULL)
        free(cb->sync_file_tmp);

    free(cb);
}

/**
 * \internal
 * \brief Encrypt clipboard data.
 *
 * \param data           The clipboard data.
 * \param data_len       Length of clipboard data.
 * \param ciphertext     The ciphertext.
 * \param ciphertext_len Length of the ciphertext.
 * \param nonce          Nonce used to encrypt the data.
 * \param key            Key used to encrypt the data.
 */
static void cb_data_encrypt(unsigned char *data, size_t data_len,
	       	            unsigned char **ciphertext, size_t *ciphertext_len,
		            unsigned char **nonce, unsigned char *key)
{
    *ciphertext_len = crypto_secretbox_MACBYTES + data_len;

    *ciphertext = calloc(1, *ciphertext_len);
    if (*ciphertext == NULL) {
        return;
    }

    *nonce = calloc(1, crypto_secretbox_NONCEBYTES);
    if (*nonce == NULL) {
        free(*ciphertext);
	return;
    }

    randombytes_buf(*nonce, sizeof(*nonce));

    crypto_secretbox_easy(*ciphertext, data, data_len, *nonce, key);
}

/**
 * \internal
 * \brief Decrypt clipboard data.
 *
 * \param ciphertext     The ciphertext.
 * \param ciphertext_len Length of the ciphertext.
 * \param nonce          Nonce used to encrypt the data
 * \param key            Key used to encrypt the data.
 *
 * \retval data on success.
 * \retval NULL on error.
 */
static char *cb_data_decrypt(unsigned char *ciphertext, size_t ciphertext_len,
                             unsigned char *nonce, unsigned char *key)
{
    unsigned char *data = calloc(1, ciphertext_len);
    if (data == NULL) {
        return NULL;
    }

    if (crypto_secretbox_open_easy(data, ciphertext, ciphertext_len, nonce,
                                   key) != 0) {
        log_error("Error: clipboard data looks forged!\n");
	free(data);
        return NULL;
    }

    return (char *)data;
}

/**
 * \brief Write clipboard data to sync file.
 *
 * \param data The clipboard data.
 * \param cb   Pointer to the clipboard state.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int cb_sync_file_write(const char *data, CBState *cb)
{
    assert(data);
    assert(cb);

    int ret = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *nonce = NULL;

    char *tmp_file = strdup(cb->sync_file_tmp);

    int fd = mkstemp(tmp_file);
    if (fd == -1) {
        log_error("Could not create tmp sync file '%s': %s\n", tmp_file,
                  strerror(errno));
	ret = -1;
	goto end;
    }

    size_t ciphertext_len = 0;
    cb_data_encrypt((unsigned char *)data, strlen(data), &ciphertext,
		    &ciphertext_len, &nonce, (unsigned char *)cb->key);
    if (ciphertext == NULL || nonce == NULL) {
        log_error("Error encrypting clipboard data\n");
	ret = -1;
	goto end;
    }

    if (write(fd, nonce, crypto_secretbox_NONCEBYTES) == -1) {
        log_error("Error writing nonce to tmp sync file '%s': %s\n", tmp_file,
                  strerror(errno));
    }

    if (write(fd, ciphertext, ciphertext_len) == -1) {
        log_error("Error writing ciphertext to tmp sync file '%s': %s\n",
                  tmp_file, strerror(errno));
	ret = -1;
	goto end;
    }

    if (fsync(fd) == -1) {
        log_error("Error syncing tmp sync file '%s' to disk: %s\n", tmp_file,
                  strerror(errno));
	ret = -1;
	goto end;
    }

    struct stat attr;
    if (fstat(fd, &attr) == -1) {
        log_error("Error stat'ing tmp sync file '%s': %s\n", tmp_file,
                  strerror(errno));
	ret = -1;
	goto end;
    }
    cb->last_modified = attr.st_mtim;

    if (close(fd) == -1) {
        log_error("Error closing tmp sync file '%s': %s\n", tmp_file,
                  strerror(errno));
	ret = -1;
	goto end;
    }

    if (rename(tmp_file, cb->sync_file) == -1) {
        log_error("Error renaming tmp sync file from '%s' to '%s': %s\n",
                  tmp_file, cb->sync_file, strerror(errno));
	ret = -1;
	goto end;
    }

end:
    free(tmp_file);

    if (ciphertext != NULL)
        free(ciphertext);

    if (nonce != NULL)
        free(nonce);

    return ret;
}

/**
 * \internal
 * \brief Synchronize clipboard to file.
 *
 * \param cb Pointer to the clipboard state.
 *
 * \retval 0 if clipboard data has not changed.
 * \retval 1 if clipboard data has changed.
 * \retval -1 on error.
 */
static int cb_sync_clipboard_to_file(CBState *cb)
{
    assert(cb);

    char *data = clipboard_text_ex(cb->clipboard, NULL, cb->mode);
    if (data == NULL) {
        return 0;
    }

    uint32_t hash[4];
    MurmurHash3_x86_128(data, strlen(data), global_seed, hash);
    if (memcmp(hash, cb->hash, sizeof(hash)) == 0) {
        /* No changes */
        free(data);
        return 0;
    }

    memcpy(cb->hash, hash, sizeof(hash));

    int r = cb_sync_file_write(data, cb);
    if (r == -1) {
        free(data);
	return -1;
    }

    free(data);
    return 1;
}

/**
 * \brief Read clipboard data from sync file.
 *
 * \param cb   Pointer to the clipboard state.
 *
 * \retval data on success.
 * \retval NULL on failure.
 */
char *cb_sync_file_read(CBState *cb)
{
    assert(cb);

    FILE *fp = fopen(cb->sync_file, "r");
    if (fp == NULL) {
        log_error("Error: could not read sync file '%s': %s\n", cb->sync_file,
                  strerror(errno));
	return NULL;
    }

    /* Get the number of bytes */
    fseek(fp, 0L, SEEK_END);
    uint32_t num_bytes = ftell(fp);

    if (num_bytes <= crypto_secretbox_NONCEBYTES) {
        log_error("Error: sync file '%s' is too small\n",
                  cb->sync_file);
    }
    num_bytes = num_bytes - crypto_secretbox_NONCEBYTES;

    /* Fail if sync file is larger than 100mb to avoid memory starvation */
    if (num_bytes > CLIPSYNC_SYNC_FILE_MAX_SIZE) {
        log_error("Error: sync file '%s' is too large (>100mb)\n",
                  cb->sync_file);
	fclose(fp);
	return NULL;
    }

    /* Reset the file position */
    fseek(fp, 0L, SEEK_SET);

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t read = fread(nonce, 1, crypto_secretbox_NONCEBYTES, fp);
    if (read != crypto_secretbox_NONCEBYTES) {
        if (ferror(fp)) {
            log_error("Error occurred when reading nonce from sync file '%s'\n",
                      cb->sync_file);
	    fclose(fp);
	    return NULL;
	}
    }

    char *ciphertext = calloc(num_bytes, sizeof(char));
    if (ciphertext == NULL) {
        log_error("Error allocating '%" PRIu32 " bytes when reading sync "
                  "file '%s'\n", num_bytes, cb->sync_file);
	fclose(fp);
	return NULL;
    }

    read = fread(ciphertext, 1, num_bytes, fp);
    if (read != num_bytes) {
        if (ferror(fp)) {
            log_error("Error occurred when reading sync file '%s'\n",
                      cb->sync_file);
	    fclose(fp);
	    return NULL;
	}
    }

    if (fclose(fp) != 0) {
        log_error("Error closing sync file '%s': %s\n", cb->sync_file,
                  strerror(errno));
	free(ciphertext);
	return NULL;
    }

    char *data = cb_data_decrypt((unsigned char *)ciphertext,
		                 num_bytes, nonce,
				 (unsigned char *)cb->key);
    if (data == NULL) {
        log_error("Error decrypting data from '%s'\n", cb->sync_file);
	free(ciphertext);
        return NULL;
    }

    free(ciphertext);

    return data;
}

/**
 * \internal
 * \brief Synchronize file to clipboard.
 *
 * \param cb Pointer to the clipboard state.
 *
 * \retval 0 if no modifications has been made to the file.
 * \retval 1 if modifications has been made to the file..
 * \retval -1 on error.
 */
static int cb_sync_file_to_clipboard(CBState *cb)
{
    assert(cb);

    if (access(cb->sync_file, F_OK) == -1) {
        /* File does not exist */
        return 0;
    }

    struct stat attr;
    if (stat(cb->sync_file, &attr) == -1) {
        log_error("Error stat'ing sync file '%s': %s\n", cb->sync_file,
                  strerror(errno));
	return -1;
    }

    if (attr.st_mtim.tv_sec == cb->last_modified.tv_sec) {
        if (attr.st_mtim.tv_nsec <= cb->last_modified.tv_nsec) {
            /* No changes */
            return 0;
        }
    } else if (attr.st_mtim.tv_sec <= cb->last_modified.tv_sec) {
        /* No changes */
        return 0;
    }

    cb->last_modified = attr.st_mtim;

    char *data = cb_sync_file_read(cb);
    if (data == NULL) {
        return -1;
    }

    clipboard_set_text_ex(cb->clipboard, data, strlen(data), cb->mode);

    free(data);
    return 1;
}

/**
 * \brief Synchronize clipboard.
 *
 * \param cb Pointer to the clipboard state.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int cb_sync(CBState *cb)
{
    if (cb == NULL)
        return -1;

    int r = cb_sync_clipboard_to_file(cb);
    if (r == 1) {
        /* Clipboard data was written to file, so therefore skip the rest
	   of the function. */
        return 0;
    } else if (r == -1) {
        return -1;
    }

    r = cb_sync_file_to_clipboard(cb);
    if (r == -1) {
        return -1;
    }

    return 0;
}

