#include "fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZERO_CHUNK_SIZE 131072U  // 128 KiB overwrite buffer

struct FileReader {
    int fd;
};

struct FileWriter {
    int fd;
    char *tmp_path;
    char *final_path;
};

/* Opens a regular file owned by the current user without following symlinks (TOCTOU-safe). */
static FileIoStatus open_verified(const char *path, int flags, int *out_fd, uint64_t *out_size) {
    const int fd = open(path, flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) return FILEIO_ERR_NOT_FOUND;
        if (errno == ELOOP)  return FILEIO_ERR_NOT_REGULAR;
        return FILEIO_ERR_OPEN;
    }

    struct stat st;
    FileIoStatus err = FILEIO_OK;
    if (fstat(fd, &st) != 0)                                           err = FILEIO_ERR_READ;
    else if (!S_ISREG(st.st_mode))                                     err = FILEIO_ERR_NOT_REGULAR;
    else if (st.st_uid != geteuid())                                   err = FILEIO_ERR_OWNER;
    else if (st.st_size < 0 || (uint64_t)st.st_size > FILEIO_MAX_SIZE) err = FILEIO_ERR_TOO_BIG;

    if (err != FILEIO_OK) {
        (void)close(fd);
        return err;
    }
    *out_fd = fd;
    *out_size = (uint64_t)st.st_size;
    return FILEIO_OK;
}

static bool write_all(int fd, const unsigned char *buf, size_t len) {
    for (size_t done = 0; done < len;) {
        const ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        done += (size_t)n;
    }
    return true;
}

static void writer_destroy(FileWriter *writer) {
    (void)unlink(writer->tmp_path);
    free(writer->tmp_path);
    free(writer->final_path);
    free(writer);
}

FileIoStatus fileio_reader_open(const char *path, FileReader **reader, uint64_t *size) {
    if (path == nullptr || reader == nullptr || size == nullptr) return FILEIO_ERR_ARGS;

    int fd = -1;
    uint64_t file_size = 0;
    const FileIoStatus st = open_verified(path, O_RDONLY, &fd, &file_size);
    if (st != FILEIO_OK) return st;

    FileReader *r = malloc(sizeof *r);
    if (r == nullptr) { (void)close(fd); return FILEIO_ERR_ALLOC; }

    *r = (FileReader){.fd = fd};
    *reader = r;
    *size = file_size;
    return FILEIO_OK;
}

FileIoStatus fileio_reader_read(FileReader *reader, unsigned char *buf, size_t want, size_t *got) {
    if (reader == nullptr || (buf == nullptr && want > 0) || got == nullptr) return FILEIO_ERR_ARGS;

    size_t done = 0;
    while (done < want) {
        const ssize_t n = read(reader->fd, buf + done, want - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FILEIO_ERR_READ;
        }
        if (n == 0) break;
        done += (size_t)n;
    }
    *got = done;
    return FILEIO_OK;
}

void fileio_reader_close(FileReader *reader) {
    if (reader == nullptr) return;
    (void)close(reader->fd);
    free(reader);
}

FileIoStatus fileio_writer_create(const char *path, FileWriter **writer) {
    if (path == nullptr || writer == nullptr) return FILEIO_ERR_ARGS;

    struct stat st;
    if (lstat(path, &st) == 0) return FILEIO_ERR_EXISTS;

    const char *slash = strrchr(path, '/');
    const int dir_len = (slash != nullptr) ? (int)(slash - path + 1) : 0;
    char tmp_path[4096 + 32];
    const int n = snprintf(tmp_path, sizeof tmp_path, "%.*s.sfm-tmp-XXXXXX", dir_len, path);
    if (n < 0 || (size_t)n >= sizeof tmp_path) return FILEIO_ERR_OPEN;

    const int fd = mkstemp(tmp_path);
    if (fd < 0) return FILEIO_ERR_OPEN;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);

    FileWriter *w = malloc(sizeof *w);
    char *tmp_copy = strdup(tmp_path);
    char *final_copy = strdup(path);
    if (w == nullptr || tmp_copy == nullptr || final_copy == nullptr) {
        free(w);
        free(tmp_copy);
        free(final_copy);
        (void)close(fd);
        (void)unlink(tmp_path);
        return FILEIO_ERR_ALLOC;
    }

    *w = (FileWriter){.fd = fd, .tmp_path = tmp_copy, .final_path = final_copy};
    *writer = w;
    return FILEIO_OK;
}

FileIoStatus fileio_writer_write(FileWriter *writer, const unsigned char *data, size_t len) {
    if (writer == nullptr || (data == nullptr && len > 0)) return FILEIO_ERR_ARGS;
    return write_all(writer->fd, data, len) ? FILEIO_OK : FILEIO_ERR_WRITE;
}

FileIoStatus fileio_writer_finish(FileWriter *writer) {
    if (writer == nullptr) return FILEIO_ERR_ARGS;

    FileIoStatus result = FILEIO_OK;
    const bool flushed = (fsync(writer->fd) == 0);
    const bool closed = (close(writer->fd) == 0);
    if (!flushed || !closed) {
        result = FILEIO_ERR_WRITE;
    } else if (link(writer->tmp_path, writer->final_path) != 0) {
        result = (errno == EEXIST) ? FILEIO_ERR_EXISTS : FILEIO_ERR_WRITE;
    }

    writer_destroy(writer);
    return result;
}

void fileio_writer_abort(FileWriter *writer) {
    if (writer == nullptr) return;
    (void)close(writer->fd);
    writer_destroy(writer);
}

FileIoStatus fileio_secure_delete(const char *path) {
    if (path == nullptr) return FILEIO_ERR_ARGS;

    int fd = -1;
    uint64_t remaining = 0;
    const FileIoStatus st = open_verified(path, O_RDWR, &fd, &remaining);
    if (st != FILEIO_OK) return st;

    unsigned char *zeros = calloc(1, ZERO_CHUNK_SIZE);
    if (zeros == nullptr) { (void)close(fd); return FILEIO_ERR_ALLOC; }

    bool ok = true;
    while (remaining > 0 && ok) {
        const size_t chunk = (remaining < ZERO_CHUNK_SIZE) ? (size_t)remaining : ZERO_CHUNK_SIZE;
        ok = write_all(fd, zeros, chunk);
        remaining -= chunk;
    }
    free(zeros);

    const bool synced = ok && (fsync(fd) == 0);
    const bool closed = (close(fd) == 0);
    if (!synced || !closed) return FILEIO_ERR_WRITE;

    if (unlink(path) != 0) return (errno == ENOENT) ? FILEIO_ERR_NOT_FOUND : FILEIO_ERR_WRITE;
    return FILEIO_OK;
}

const char *fileio_strerror(FileIoStatus status) {
    static const char *const messages[] = {
        [FILEIO_OK]              = "ok",
        [FILEIO_ERR_ARGS]        = "invalid arguments (internal error)",
        [FILEIO_ERR_NOT_FOUND]   = "file not found",
        [FILEIO_ERR_OPEN]        = "cannot open or create the file (permissions?)",
        [FILEIO_ERR_NOT_REGULAR] = "not a regular file (directories, devices and symlinks are refused)",
        [FILEIO_ERR_OWNER]       = "file belongs to another user",
        [FILEIO_ERR_TOO_BIG]     = "exceeds the size limit (256 GiB)",
        [FILEIO_ERR_READ]        = "error while reading the file",
        [FILEIO_ERR_ALLOC]       = "out of memory",
        [FILEIO_ERR_EXISTS]      = "output file already exists (not overwritten)",
        [FILEIO_ERR_WRITE]       = "error while writing the file",
    };
    const size_t idx = (size_t)status;
    return (idx < sizeof messages / sizeof messages[0] && messages[idx] != nullptr)
           ? messages[idx] : "unknown error";
}