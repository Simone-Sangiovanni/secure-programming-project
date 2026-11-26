#include "validate.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static_assert(VALIDATE_PATH_MAX >= PATH_MAX, "VALIDATE_PATH_MAX smaller than PATH_MAX");

bool validate_has_traversal(const char *path) {
    if (path == nullptr) return false;
    const size_t len = strlen(path);
    return strstr(path, "/../") != nullptr ||
           strstr(path, "/./") != nullptr ||
           (len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
           (len >= 2 && strcmp(path + len - 2, "/.") == 0);
}

static ValidateStatus validate_base_path(const char *path, bool allow_trailing_slash) {
    if (path == nullptr || path[0] == '\0') return VALIDATE_ERR_EMPTY;
    if (path[0] != '/') return VALIDATE_ERR_NOT_ABSOLUTE;

    const size_t len = strnlen(path, VALIDATE_PATH_MAX);
    if (len >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;
    if (!allow_trailing_slash && path[len - 1] == '/') return VALIDATE_ERR_NOT_A_FILE;
    return validate_has_traversal(path) ? VALIDATE_ERR_TRAVERSAL : VALIDATE_OK;
}

static bool resolve_existing_dir(const char *dir, char out[PATH_MAX]) {
    struct stat st;
    return realpath(dir, out) != nullptr && stat(out, &st) == 0 && S_ISDIR(st.st_mode);
}

ValidateStatus validate_absolute_path(const char *path) {
    return validate_base_path(path, false);
}

ValidateStatus validate_file_path(const char *path, char resolved_out[VALIDATE_PATH_MAX]) {
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

ValidateStatus validate_directory_path(const char *path, char resolved_out[VALIDATE_PATH_MAX]) {
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
    static const char *const messages[] = {
        [VALIDATE_OK]               = "ok",
        [VALIDATE_ERR_EMPTY]        = "path is empty",
        [VALIDATE_ERR_NOT_ABSOLUTE] = "path must be absolute (start with '/')",
        [VALIDATE_ERR_TOO_LONG]     = "path is too long",
        [VALIDATE_ERR_NOT_A_FILE]   = "path must name a file, not a directory",
        [VALIDATE_ERR_TRAVERSAL]    = "path contains traversal components (.. or .)",
        [VALIDATE_ERR_NOT_A_DIR]    = "destination is not an existing directory",
        [VALIDATE_ERR_PARENT]       = "the parent directory of the file does not exist or is not a directory",
    };
    const size_t idx = (size_t)status;
    return (idx < sizeof messages / sizeof messages[0] && messages[idx] != nullptr)
           ? messages[idx] : "unknown error";
}