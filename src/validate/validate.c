#include "validate.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static_assert(VALIDATE_PATH_MAX >= PATH_MAX, "VALIDATE_PATH_MAX smaller than PATH_MAX");

static bool has_traversal_component(const char *path, size_t len) {
    return strstr(path, "/../") != nullptr ||
           strstr(path, "/./") != nullptr ||
           (len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
           (len >= 2 && strcmp(path + len - 2, "/.") == 0);
}

ValidateStatus validate_absolute_path(const char *path) {
    if (path == nullptr || path[0] == '\0') return VALIDATE_ERR_EMPTY;
    if (path[0] != '/') return VALIDATE_ERR_NOT_ABSOLUTE;

    const size_t len = strnlen(path, VALIDATE_PATH_MAX);
    if (len >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;

    if (path[len - 1] == '/') return VALIDATE_ERR_NOT_A_FILE;

    if (has_traversal_component(path, len)) {
        return VALIDATE_ERR_TRAVERSAL;
    }

    return VALIDATE_OK;
}

ValidateStatus validate_file_path(const char *path,
                                  char resolved_out[VALIDATE_PATH_MAX]) {
    if (resolved_out == nullptr) return VALIDATE_ERR_EMPTY;

    const ValidateStatus vs = validate_absolute_path(path);
    if (vs != VALIDATE_OK) return vs;

    // validate_absolute_path guarantees a leading '/', no trailing '/', and
    // therefore a non-empty file name after the last '/'.
    const char *slash = strrchr(path, '/');
    const char *name = slash + 1;
    const size_t parent_len = (size_t)(slash - path);

    char parent[VALIDATE_PATH_MAX];
    if (parent_len == 0) {
        parent[0] = '/';
        parent[1] = '\0';
    } else {
        memcpy(parent, path, parent_len);
        parent[parent_len] = '\0';
    }

    char canonical[PATH_MAX];
    if (realpath(parent, canonical) == nullptr) return VALIDATE_ERR_PARENT;

    struct stat st;
    if (stat(canonical, &st) != 0 || !S_ISDIR(st.st_mode)) return VALIDATE_ERR_PARENT;

    const char *sep = (strcmp(canonical, "/") == 0) ? "" : "/";
    const int n = snprintf(resolved_out, VALIDATE_PATH_MAX, "%s%s%s", canonical, sep, name);
    if (n < 0 || (size_t)n >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;

    return VALIDATE_OK;
}

ValidateStatus validate_directory_path(const char *path,
                                     char resolved_out[VALIDATE_PATH_MAX]) {
    if (path == nullptr || path[0] == '\0') return VALIDATE_ERR_EMPTY;
    if (path[0] != '/') return VALIDATE_ERR_NOT_ABSOLUTE;

    const size_t len = strnlen(path, VALIDATE_PATH_MAX);
    if (len >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;

    if (has_traversal_component(path, len)) {
        return VALIDATE_ERR_TRAVERSAL;
    }

    char canonical[PATH_MAX];
    if (realpath(path, canonical) == nullptr) {
        return VALIDATE_ERR_NOT_A_DIR;
    }

    struct stat st;
    if (stat(canonical, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return VALIDATE_ERR_NOT_A_DIR;
    }

    if (resolved_out != nullptr) {
        const int n = snprintf(resolved_out, VALIDATE_PATH_MAX, "%s", canonical);
        if (n < 0 || (size_t)n >= VALIDATE_PATH_MAX) {
            return VALIDATE_ERR_TOO_LONG;
        }
    }

    return VALIDATE_OK;
}

const char *validate_strerror(ValidateStatus status) {
    switch (status) {
        case VALIDATE_OK:               return "ok";
        case VALIDATE_ERR_EMPTY:        return "path is empty";
        case VALIDATE_ERR_NOT_ABSOLUTE: return "path must be absolute (start with '/')";
        case VALIDATE_ERR_TOO_LONG:     return "path is too long";
        case VALIDATE_ERR_NOT_A_FILE:   return "path must name a file, not a directory";
        case VALIDATE_ERR_TRAVERSAL:    return "path contains traversal components (.. or .)";
        case VALIDATE_ERR_NOT_A_DIR:    return "destination is not an existing directory";
        case VALIDATE_ERR_PARENT:       return "the parent directory of the file does not exist or is not a directory";
    }
    return "unknown error";
}
