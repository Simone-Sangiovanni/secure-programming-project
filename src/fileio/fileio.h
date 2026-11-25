#ifndef SFM_FILEIO_H
#define SFM_FILEIO_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file fileio.h
 * @brief Streaming file I/O: chunked reading, atomic new-file writing, and secure deletion.
 *
 * Centralizes size limits and permission checks so nothing holds an entire file in memory.
 */

#define FILEIO_MAX_SIZE (256ULL * 1024ULL * 1024ULL * 1024ULL)

/** Result codes returned by fileio functions. */
typedef enum {
    FILEIO_OK = 0,           /**< Success. */
    FILEIO_ERR_ARGS,         /**< NULL pointer or invalid argument passed by caller. */
    FILEIO_ERR_NOT_FOUND,    /**< File does not exist. */
    FILEIO_ERR_OPEN,         /**< Cannot open or create file (permissions, bad path, etc.). */
    FILEIO_ERR_NOT_REGULAR,  /**< Not a regular file (directory, symlink, device, pipe, etc.). */
    FILEIO_ERR_OWNER,        /**< File belongs to another user. */
    FILEIO_ERR_TOO_BIG,      /**< Exceeds FILEIO_MAX_SIZE. */
    FILEIO_ERR_READ,         /**< Read failed or file changed while reading. */
    FILEIO_ERR_ALLOC,        /**< Out of memory. */
    FILEIO_ERR_EXISTS,       /**< Output file already exists (never overwritten). */
    FILEIO_ERR_WRITE         /**< Write, flush, or close failed. */
} FileIoStatus;

typedef struct FileReader FileReader;
typedef struct FileWriter FileWriter;

/**
 * @brief Opens a regular file owned by the current user for reading and reports its size.
 *
 * Refuses symlinks, non-regular files (directories, FIFOs, devices), files owned
 * by another UID, and files larger than FILEIO_MAX_SIZE.
 *
 * @param path   File to open.
 * @param reader Receives the handle on success (release with fileio_reader_close()).
 * @param size   Receives the file size in bytes on success.
 * @return FILEIO_OK on success, or an error status (nothing is allocated on failure).
 */
[[nodiscard]] FileIoStatus fileio_reader_open(const char *path, FileReader **reader, uint64_t *size);

/** Reads up to @p want bytes, retrying until @p want bytes are read or EOF is reached. */
[[nodiscard]] FileIoStatus fileio_reader_read(FileReader *reader, unsigned char *buf,
                                              size_t want, size_t *got);

/** Closes a reader and frees its handle. Safe to call with NULL. */
void fileio_reader_close(FileReader *reader);

/** Starts writing a new file (fails with FILEIO_ERR_EXISTS if @p path already exists). */
[[nodiscard]] FileIoStatus fileio_writer_create(const char *path, FileWriter **writer);

/** Appends @p len bytes to the output file. */
[[nodiscard]] FileIoStatus fileio_writer_write(FileWriter *writer, const unsigned char *data, size_t len);

/** Flushes to disk, closes, and atomically publishes the output file without overwriting. */
[[nodiscard]] FileIoStatus fileio_writer_finish(FileWriter *writer);

/** Aborts writing, closes the file, and removes the temporary file. Safe to call with NULL. */
void fileio_writer_abort(FileWriter *writer);

/**
 * @brief Overwrites a regular file owned by the current user with zeros, flushes
 *        it (fsync), and unlinks it.
 *
 * Note: overwriting before unlink() is best-effort on SSDs and journaling or
 * copy-on-write filesystems.
 */
[[nodiscard]] FileIoStatus fileio_secure_delete(const char *path);

/** Returns a human-readable message for @p status (never NULL). */
[[nodiscard]] const char *fileio_strerror(FileIoStatus status);

#endif
