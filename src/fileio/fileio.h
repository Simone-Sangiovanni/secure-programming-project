#ifndef SFM_FILEIO_H
#define SFM_FILEIO_H

#include <stddef.h>
#include <stdint.h>

#define FILEIO_MAX_SIZE (256ULL * 1024ULL * 1024ULL * 1024ULL)

typedef enum {
    FILEIO_OK = 0,
    FILEIO_ERR_ARGS,
    FILEIO_ERR_NOT_FOUND,
    FILEIO_ERR_OPEN,
    FILEIO_ERR_NOT_REGULAR,
    FILEIO_ERR_OWNER,
    FILEIO_ERR_TOO_BIG,
    FILEIO_ERR_READ,
    FILEIO_ERR_ALLOC,
    FILEIO_ERR_EXISTS,
    FILEIO_ERR_WRITE
} FileIoStatus;

typedef struct FileReader FileReader;
typedef struct FileWriter FileWriter;

[[nodiscard]] FileIoStatus fileio_reader_open(const char *path, FileReader **reader, uint64_t *size);
[[nodiscard]] FileIoStatus fileio_reader_read(FileReader *reader, unsigned char *buf,
                                              size_t want, size_t *got);
void fileio_reader_close(FileReader *reader);

[[nodiscard]] FileIoStatus fileio_writer_create(const char *path, FileWriter **writer);
[[nodiscard]] FileIoStatus fileio_writer_write(FileWriter *writer, const unsigned char *data, size_t len);
[[nodiscard]] FileIoStatus fileio_writer_finish(FileWriter *writer);
void fileio_writer_abort(FileWriter *writer);

[[nodiscard]] FileIoStatus fileio_secure_delete(const char *path);
[[nodiscard]] const char *fileio_strerror(FileIoStatus status);

#endif