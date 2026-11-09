#define _POSIX_C_SOURCE 200809L  // open, fstat, fsync, strdup, O_CLOEXEC
#define FILE_OFFSET_BITS 64     // 64-bit file sizes even on 32-bit systems

#include "fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

struct FileReader {
    int fd;
};

struct FileWriter {
    int fd;
    char *tmp_path;    // the temporary file being written (removed on abort)
    char *final_path;  // where it is published when finished
};

FileIoStatus fileio_reader_open(const char *path, FileReader **reader, uint64_t *size) {
    if (path == nullptr || reader == nullptr || size == nullptr) return FILEIO_ERR_ARGS;

    // O_NOFOLLOW: refuse to open a symbolic link (it could point anywhere).
    const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) return FILEIO_ERR_NOT_FOUND;
        if (errno == ELOOP) return FILEIO_ERR_NOT_REGULAR;  // it is a symlink
        return FILEIO_ERR_OPEN;
    }

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
    if (st.st_size < 0 || (uint64_t)st.st_size > FILEIO_MAX_SIZE) {
        (void)close(fd);
        return FILEIO_ERR_TOO_BIG;
    }

    FileReader *r = malloc(sizeof *r);
    if (r == nullptr) {
        (void)close(fd);
        return FILEIO_ERR_ALLOC;
    }
    r->fd = fd;

    *reader = r;
    *size = (uint64_t)st.st_size;
    return FILEIO_OK;
}

FileIoStatus fileio_reader_read(FileReader *reader, unsigned char *buf, size_t want, size_t *got) {
    if (reader == nullptr || (buf == nullptr && want > 0) || got == nullptr) return FILEIO_ERR_ARGS;

    size_t done = 0;
    while (done < want) {
        const ssize_t n = read(reader->fd, buf + done, want - done);
        if (n < 0) {
            if (errno == EINTR) continue;  // interrupted by a signal: retry
            return FILEIO_ERR_READ;
        }
        if (n == 0) break;  // end of file
        done += (size_t)n;
    }
    *got = done;
    return FILEIO_OK;
}

void fileio_reader_close(FileReader *reader) {
    if (reader == nullptr) return;
    (void)close(reader->fd);  // read-only: a close failure loses no data
    free(reader);
}

FileIoStatus fileio_writer_create(const char *path, FileWriter **writer) {
    if (path == nullptr || writer == nullptr) return FILEIO_ERR_ARGS;

    // Fail early (before any work is done) if the destination already exists.
    // lstat also counts a symlink, even a dangling one. This is only a courtesy:
    // the authoritative check is the atomic link() in fileio_writer_finish().
    struct stat st;
    if (lstat(path, &st) == 0) return FILEIO_ERR_EXISTS;

    // Temporary file in the SAME directory as the destination (needed so the
    // final publish is atomic). The name is random and short, so it never
    // collides with a leftover and does not depend on the length of `path`.
    // mkstemp creates it exclusively (O_EXCL) with permissions 0600.
    const char *slash = strrchr(path, '/');
    const int dir_len = (slash != nullptr) ? (int)(slash - path + 1) : 0;
    char tmp_path[4096 + 32];
    const int n = snprintf(tmp_path, sizeof tmp_path, "%.*s.sfm-tmp-XXXXXX", dir_len, path);
    if (n < 0 || (size_t)n >= sizeof tmp_path) return FILEIO_ERR_OPEN;  // path too long

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
        (void)unlink(tmp_path);  // do not leave the temporary file behind
        return FILEIO_ERR_ALLOC;
    }
    w->fd = fd;
    w->tmp_path = tmp_copy;
    w->final_path = final_copy;

    *writer = w;
    return FILEIO_OK;
}

FileIoStatus fileio_writer_write(FileWriter *writer, const unsigned char *data, size_t len) {
    if (writer == nullptr || (data == nullptr && len > 0)) return FILEIO_ERR_ARGS;

    size_t done = 0;
    while (done < len) {
        const ssize_t n = write(writer->fd, data + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return FILEIO_ERR_WRITE;
        }
        done += (size_t)n;
    }
    return FILEIO_OK;
}

FileIoStatus fileio_writer_finish(FileWriter *writer) {
    if (writer == nullptr) return FILEIO_ERR_ARGS;

    FileIoStatus result = FILEIO_OK;

    bool ok = (fsync(writer->fd) == 0);      // make sure the data reached the disk
    ok = (close(writer->fd) == 0) && ok;     // close can report deferred write errors
    if (!ok) {
        result = FILEIO_ERR_WRITE;
    } else if (link(writer->tmp_path, writer->final_path) != 0) {
        // Publish WITHOUT replacing: link() fails atomically with EEXIST if the
        // destination exists (rename() would silently overwrite it).
        result = (errno == EEXIST) ? FILEIO_ERR_EXISTS : FILEIO_ERR_WRITE;
    }

    // Success: the data now lives under its final name. Failure: discard it.
    (void)unlink(writer->tmp_path);

    free(writer->tmp_path);
    free(writer->final_path);
    free(writer);
    return result;
}

void fileio_writer_abort(FileWriter *writer) {
    if (writer == nullptr) return;
    (void)close(writer->fd);
    (void)unlink(writer->tmp_path);
    free(writer->tmp_path);
    free(writer->final_path);
    free(writer);
}

const char *fileio_strerror(FileIoStatus status) {
    switch (status) {
        case FILEIO_OK:              return "ok";
        case FILEIO_ERR_ARGS:        return "invalid arguments (internal error)";
        case FILEIO_ERR_NOT_FOUND:   return "file not found";
        case FILEIO_ERR_OPEN:        return "cannot open or create the file (permissions?)";
        case FILEIO_ERR_NOT_REGULAR: return "not a regular file (directories, devices and symlinks are refused)";
        case FILEIO_ERR_TOO_BIG:     return "exceeds the size limit (256 GiB)";
        case FILEIO_ERR_READ:        return "error while reading the file";
        case FILEIO_ERR_ALLOC:       return "out of memory";
        case FILEIO_ERR_EXISTS:      return "output file already exists (not overwritten)";
        case FILEIO_ERR_WRITE:       return "error while writing the file";
    }
    return "unknown error";
}