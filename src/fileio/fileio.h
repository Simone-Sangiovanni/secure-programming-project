#ifndef SFM_FILEIO_H
#define SFM_FILEIO_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file fileio.h
 * @brief Streaming access to files: read a file piece by piece, write a new
 *        file piece by piece.
 *
 * This is the only module the encrypt/decrypt code uses to touch the disk,
 * so limits and permissions are enforced in one place. Nothing here keeps a
 * whole file in memory.
 */

/**
 * Largest file that will be read or written: 256 GiB = 274,877,906,944 bytes.
 *
 * It applies to the input AND to the encrypted output. Encryption adds a
 * small overhead (17 bytes per 128 KiB chunk, about 34 MiB at this size), so
 * the largest plaintext that can be encrypted is slightly below 256 GiB.
 */
#define FILEIO_MAX_SIZE (256ULL * 1024ULL * 1024ULL * 1024ULL)

/** Result codes returned by the fileio functions. */
typedef enum {
    FILEIO_OK = 0,           /**< Success. */
    FILEIO_ERR_ARGS,         /**< NULL pointer passed by the caller (a bug). */
    FILEIO_ERR_NOT_FOUND,    /**< The file does not exist. */
    FILEIO_ERR_OPEN,         /**< Cannot open/create (permissions, bad path, ...). */
    FILEIO_ERR_NOT_REGULAR,  /**< Not a regular file (directory, device, pipe...). */
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
 * @brief Opens a regular file for reading and reports its size.
 *
 * Rejects anything that is not a regular file, and files larger than
 * FILEIO_MAX_SIZE.
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
 *
 * A result with *got < want means the end of the file was reached.
 *
 * @param reader Open reader.
 * @param buf    Destination buffer of at least @p want bytes.
 * @param want   Number of bytes wanted.
 * @param got    Receives the number of bytes actually read.
 * @return FILEIO_OK or FILEIO_ERR_READ.
 */
[[nodiscard]] FileIoStatus fileio_reader_read(FileReader *reader, unsigned char *buf,
                                              size_t want, size_t *got);

/** Closes a reader. Safe to call with NULL. */
void fileio_reader_close(FileReader *reader);

/**
 * @brief Starts writing a NEW file.
 *
 * Nothing appears under @p path until fileio_writer_finish() succeeds: the
 * data goes to a temporary file (random name, same directory, permissions
 * 0600), so a crash, a failure or an abort never leaves a partial file under
 * the final name. An existing file at @p path is never replaced
 * (FILEIO_ERR_EXISTS).
 *
 * @param path   Final path of the file to create.
 * @param writer Receives the handle. It must end with either
 *               fileio_writer_finish() or fileio_writer_abort().
 * @return FILEIO_OK or the reason it failed (nothing is left on disk on failure).
 */
[[nodiscard]] FileIoStatus fileio_writer_create(const char *path, FileWriter **writer);

/**
 * @brief Appends bytes to the output file.
 *
 * After a failure the caller must call fileio_writer_abort().
 *
 * @param data May be NULL only if @p len is 0.
 */
[[nodiscard]] FileIoStatus fileio_writer_write(FileWriter *writer, const unsigned char *data, size_t len);

/**
 * @brief Completes the output file: flushes the temporary file to disk
 *        (fsync), closes it, and publishes it under its final name.
 *
 * Publishing is atomic and never replaces an existing file (it uses link()
 * and fails with FILEIO_ERR_EXISTS). Always frees @p writer, and the
 * temporary file is always removed. Needs a file system with hard links
 * (ext4, xfs, btrfs, tmpfs; not FAT/exFAT).
 */
[[nodiscard]] FileIoStatus fileio_writer_finish(FileWriter *writer);

/**
 * @brief Gives up on the output file: closes and removes the temporary file.
 *        Nothing was ever visible under the final name. Frees @p writer.
 *        Safe with NULL.
 *
 * Note: removing a file deletes its name, it does not erase its bytes from
 * the disk.
 */
void fileio_writer_abort(FileWriter *writer);

/** Returns a human-readable message for a FileIoStatus (never NULL). */
[[nodiscard]] const char *fileio_strerror(FileIoStatus status);

#endif