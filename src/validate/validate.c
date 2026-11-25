#include "validate.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static_assert(VALIDATE_PATH_MAX >= PATH_MAX, "VALIDATE_PATH_MAX smaller than PATH_MAX");

/* Validates syntax rules common to file and directory paths. */
static ValidateStatus validate_base_path(const char *path, bool allow_trailing_slash) {
    if (path == nullptr || path[0] == '\0') return VALIDATE_ERR_EMPTY;
    if (path[0] != '/') return VALIDATE_ERR_NOT_ABSOLUTE;

    const size_t len = strnlen(path, VALIDATE_PATH_MAX);
    if (len >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;
    if (!allow_trailing_slash && path[len - 1] == '/') return VALIDATE_ERR_NOT_A_FILE;

    const bool has_traversal =
        strstr(path, "/../") != nullptr ||
        strstr(path, "/./") != nullptr ||
        (len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
        (len >= 2 && strcmp(path + len - 2, "/.") == 0);

    return has_traversal ? VALIDATE_ERR_TRAVERSAL : VALIDATE_OK;
}

/* Resolves dir with realpath() and verifies it exists and is a directory. */
static bool resolve_existing_dir(const char *dir, char out[PATH_MAX]) {
    struct stat st;
    return realpath(dir, out) != nullptr &&
           stat(out, &st) == 0 &&
           S_ISDIR(st.st_mode);
}

ValidateStatus validate_absolute_path(const char *path) {
    return validate_base_path(path, false);
}

ValidateStatus validate_file_path(const char *path,
                                  char resolved_out[VALIDATE_PATH_MAX]) {
    if (resolved_out == nullptr) return VALIDATE_ERR_EMPTY;

    const ValidateStatus status = validate_base_path(path, false);
    if (status != VALIDATE_OK) return status;

    const char *slash = strrchr(path, '/');
    const size_t parent_len = (slash == path) ? 1 : (size_t)(slash - path);

    char parent[VALIDATE_PATH_MAX];
    memcpy(parent, path, parent_len);
    parent[parent_len] = '\0';

    char canonical[PATH_MAX];
    if (!resolve_existing_dir(parent, canonical)) return VALIDATE_ERR_PARENT;

    const char *sep = (strcmp(canonical, "/") == 0) ? "" : "/";
    const int n = snprintf(resolved_out, VALIDATE_PATH_MAX, "%s%s%s", canonical, sep, slash + 1);
    return (n < 0 || (size_t)n >= VALIDATE_PATH_MAX) ? VALIDATE_ERR_TOO_LONG : VALIDATE_OK;
}

ValidateStatus validate_directory_path(const char *path,
                                     char resolved_out[VALIDATE_PATH_MAX]) {
    const ValidateStatus status = validate_base_path(path, true);
    if (status != VALIDATE_OK) return status;

    char canonical[PATH_MAX];
    if (!resolve_existing_dir(path, canonical)) return VALIDATE_ERR_NOT_A_DIR;

    if (resolved_out != nullptr) {
        const int n = snprintf(resolved_out, VALIDATE_PATH_MAX, "%s", canonical);
        if (n < 0 || (size_t)n >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;
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
