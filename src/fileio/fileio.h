#ifndef SFM_FILEIO_H
#define SFM_FILEIO_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file fileio.h
 * @brief Streaming access to files: read a file piece by piece, write a new
 *        file piece by piece, and securely delete files.
 *
 * This is the only module the encrypt/decrypt code uses to touch the disk,
 * so limits and permissions are enforced in one place. Nothing here keeps a
 * whole file in memory.
 */

#define FILEIO_MAX_SIZE (256ULL * 1024ULL * 1024ULL * 1024ULL)

/** Result codes returned by the fileio functions. */
typedef enum {
    FILEIO_OK = 0,           /**< Success. */
    FILEIO_ERR_ARGS,         /**< NULL pointer passed by the caller (a bug). */
    FILEIO_ERR_NOT_FOUND,    /**< The file does not exist. */
    FILEIO_ERR_OPEN,         /**< Cannot open/create (permissions, bad path, ...). */
    FILEIO_ERR_NOT_REGULAR,  /**< Not a regular file (directory, device, pipe...). */
    FILEIO_ERR_OWNER,        /**< The file belongs to another user. */
    FILEIO_ERR_TOO_BIG,      /**< Exceeds FILEIO_MAX_SIZE. */
    FILEIO_ERR_READ,         /**< Read failed or the file changed while reading. */
    FILEIO_ERR_ALLOC,        /**< Out of memory. */
    FILEIO_ERR_EXISTS,       /**< The output file already exists (never overwritten). */
    FILEIO_ERR_WRITE         /**< Write/flush/close failed. */
} FileIoStatus;

/** An open input file (opaque). */
typedef struct FileReader FileReader;

/** A new output file being written (opaque). */
typedef struct FileWriter FileWriter;

/**
 * @brief Opens a regular file owned by the current user for reading and reports its size.
 *
 * Rejects symlinks, non-regular files (directories, FIFOs, devices), files
 * owned by another UID, and files larger than FILEIO_MAX_SIZE.
 *
 * @param path   File to open.
 * @param reader Receives the handle. Release it with fileio_reader_close().
 * @param size   Receives the file size in bytes.
 * @return FILEIO_OK or the reason it failed (nothing is allocated on failure).
 */
[[nodiscard]] FileIoStatus fileio_reader_open(const char *path, FileReader **reader, uint64_t *size);

/**
 * @brief Reads up to @p want bytes, continuing until @p want bytes were read
 *        or the end of the file is reached.
 */
[[nodiscard]] FileIoStatus fileio_reader_read(FileReader *reader, unsigned char *buf,
                                              size_t want, size_t *got);

/** Closes a reader. Safe to call with NULL. */
void fileio_reader_close(FileReader *reader);

/**
 * @brief Starts writing a NEW file.
 */
[[nodiscard]] FileIoStatus fileio_writer_create(const char *path, FileWriter **writer);

/**
 * @brief Appends bytes to the output file.
 */
[[nodiscard]] FileIoStatus fileio_writer_write(FileWriter *writer, const unsigned char *data, size_t len);

/**
 * @brief Completes the output file: flushes to disk, closes, and publishes atomically.
 */
[[nodiscard]] FileIoStatus fileio_writer_finish(FileWriter *writer);

/**
 * @brief Gives up on the output file: closes and removes the temporary file.
 */
void fileio_writer_abort(FileWriter *writer);

/**
 * @brief Overwrites a regular file owned by the current user with zeros,
 *        flushes it to disk (fsync), and removes it (unlink).
 *
 * Note: overwriting before unlink() is best-effort on SSDs and journaling or
 * copy-on-write filesystems.
 *
 * @param path Path of the regular file to securely delete.
 * @return FILEIO_OK on success, or the reason deletion failed.
 */
[[nodiscard]] FileIoStatus fileio_secure_delete(const char *path);

/** Returns a human-readable message for a FileIoStatus (never NULL). */
[[nodiscard]] const char *fileio_strerror(FileIoStatus status);

#endif
