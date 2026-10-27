#ifndef SFM_FILEIO_H
#define SFM_FILEIO_H

#include <stddef.h>

/**
 * @file fileio.h
 * @brief Reading a whole file into memory and writing a new file.
 *
 * This is the only module the encrypt/decrypt commands use to touch the
 * disk, so limits and permissions are enforced in one place.
 */

/** Largest file that will be read (64 MiB). The whole file is held in memory. */
#define FILEIO_MAX_SIZE (64ULL * 1024ULL * 1024ULL)

/** Result codes returned by the fileio functions. */
typedef enum {
    FILEIO_OK = 0,           /**< Success. */
    FILEIO_ERR_ARGS,         /**< NULL pointer passed by the caller (a bug). */
    FILEIO_ERR_NOT_FOUND,    /**< The file does not exist. */
    FILEIO_ERR_OPEN,         /**< Cannot open (permissions, bad path, ...). */
    FILEIO_ERR_NOT_REGULAR,  /**< Not a regular file (directory, device, pipe...). */
    FILEIO_ERR_TOO_BIG,      /**< Larger than FILEIO_MAX_SIZE. */
    FILEIO_ERR_READ,         /**< Read failed or the file changed while reading. */
    FILEIO_ERR_ALLOC,        /**< Out of memory. */
    FILEIO_ERR_EXISTS,       /**< The output file already exists (never overwritten). */
    FILEIO_ERR_WRITE         /**< Write/flush/close failed (partial file removed). */
} FileIoStatus;

/**
 * @brief Reads a whole regular file into a new heap buffer.
 *
 * @param path Absolute or relative path of the file.
 * @param data Receives the buffer (never NULL on success, even for an empty
 *             file). The caller must wipe and free it.
 * @param len  Receives the number of bytes read.
 * @return FILEIO_OK or the reason it failed. On failure nothing is allocated.
 */
[[nodiscard]] FileIoStatus fileio_read_all(const char *path, unsigned char **data, size_t *len);

/**
 * @brief Creates a NEW file and writes @p data to it.
 *
 * Fails with FILEIO_ERR_EXISTS instead of overwriting. The file is created
 * with permissions 0600 (owner only), flushed to disk with fsync, and
 * removed again if anything goes wrong, so no half-written file is left.
 *
 * @param path Path of the file to create.
 * @param data Bytes to write (may be NULL only if @p len is 0).
 * @param len  Number of bytes.
 * @return FILEIO_OK or the reason it failed.
 */
[[nodiscard]] FileIoStatus fileio_write_new(const char *path, const unsigned char *data, size_t len);

/** Returns a human-readable message for a FileIoStatus (never NULL). */
[[nodiscard]] const char *fileio_strerror(FileIoStatus status);

#endif