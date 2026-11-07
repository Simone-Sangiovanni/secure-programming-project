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

    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
 
    // 1. Unique, random temp name in the SAME directory (a rename/link across
    //    directories or file systems would not be atomic). mkstemp creates it
    //    with O_EXCL and permissions 0600, and never collides with leftovers.
    char tmp_path[4096 + 16];
    const int n = snprintf(tmp_path, sizeof tmp_path, "%s.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof tmp_path) return FILEIO_ERR_OPEN;  // path too long
 
    const int fd = mkstemp(tmp_path);
    if (fd < 0) return FILEIO_ERR_OPEN;
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
 
    // 2. Write loop.
    bool ok = true;
    size_t done = 0;
    while (done < len) {
        const ssize_t w = write(fd, data + done, len - done);
        if (w < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        done += (size_t)w;
    }
 
    // 3. Flush to disk and close (close can report deferred write errors).
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (!ok) {
        (void)unlink(tmp_path);
        return FILEIO_ERR_WRITE;
    }
 
    // 4. Publish WITHOUT replacing. link() fails atomically with EEXIST if
    //    `path` already exists (rename() would silently overwrite it).
    if (link(tmp_path, path) != 0) {
        const int err = errno;
        (void)unlink(tmp_path);
        return (err == EEXIST) ? FILEIO_ERR_EXISTS : FILEIO_ERR_WRITE;
    }
    (void)unlink(tmp_path);  // the data now lives under its final name
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