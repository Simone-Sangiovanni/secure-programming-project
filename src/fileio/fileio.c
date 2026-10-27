#define _POSIX_C_SOURCE 200809L  // open, fstat, fsync, O_CLOEXEC

#include "fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

FileIoStatus fileio_read_all(const char *path, unsigned char **data, size_t *len) {
    if (path == nullptr || data == nullptr || len == nullptr) return FILEIO_ERR_ARGS;

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return (errno == ENOENT) ? FILEIO_ERR_NOT_FOUND : FILEIO_ERR_OPEN;

    // Ask the already-open file (not the path) about itself: no race between
    // checking and reading.
    struct stat st;
    if (fstat(fd, &st) != 0) {
        (void)close(fd);
        return FILEIO_ERR_READ;
    }
    if (!S_ISREG(st.st_mode)) {
        (void)close(fd);
        return FILEIO_ERR_NOT_REGULAR;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > FILEIO_MAX_SIZE) {
        (void)close(fd);
        return FILEIO_ERR_TOO_BIG;
    }

    const size_t size = (size_t)st.st_size;
    unsigned char *buf = malloc(size > 0 ? size : 1);  // never malloc(0)
    if (buf == nullptr) {
        (void)close(fd);
        return FILEIO_ERR_ALLOC;
    }

    size_t done = 0;
    while (done < size) {
        const ssize_t n = read(fd, buf + done, size - done);
        if (n < 0) {
            if (errno == EINTR) continue;  // interrupted by a signal: retry
            break;
        }
        if (n == 0) break;  // the file got shorter while reading
        done += (size_t)n;
    }
    (void)close(fd);  // read-only: a close failure loses no data

    if (done != size) {
        sodium_memzero(buf, size);
        free(buf);
        return FILEIO_ERR_READ;
    }

    *data = buf;
    *len = size;
    return FILEIO_OK;
}

FileIoStatus fileio_write_new(const char *path, const unsigned char *data, size_t len) {
    if (path == nullptr || (data == nullptr && len > 0)) return FILEIO_ERR_ARGS;

    // O_EXCL: fail if it exists (also refuses to follow a symlink planted there).
    // TODO(security): write to a temp file + rename() for an atomic result.
    const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) return (errno == EEXIST) ? FILEIO_ERR_EXISTS : FILEIO_ERR_OPEN;

    bool ok = true;
    size_t done = 0;
    while (done < len) {
        const ssize_t n = write(fd, data + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        done += (size_t)n;
    }
    if (ok && fsync(fd) != 0) ok = false;   // make sure the data reached the disk
    if (close(fd) != 0) ok = false;         // close can report deferred write errors

    if (!ok) {
        (void)unlink(path);  // do not leave a half-written file behind
        return FILEIO_ERR_WRITE;
    }
    return FILEIO_OK;
}

const char *fileio_strerror(FileIoStatus status) {
    switch (status) {
        case FILEIO_OK:              return "ok";
        case FILEIO_ERR_ARGS:        return "invalid arguments (internal error)";
        case FILEIO_ERR_NOT_FOUND:   return "file not found";
        case FILEIO_ERR_OPEN:        return "cannot open the file (permissions?)";
        case FILEIO_ERR_NOT_REGULAR: return "not a regular file";
        case FILEIO_ERR_TOO_BIG:     return "file is too big (limit 64 MiB)";
        case FILEIO_ERR_READ:        return "error while reading the file";
        case FILEIO_ERR_ALLOC:       return "out of memory";
        case FILEIO_ERR_EXISTS:      return "output file already exists (not overwritten)";
        case FILEIO_ERR_WRITE:       return "error while writing the file";
    }
    return "unknown error";
}