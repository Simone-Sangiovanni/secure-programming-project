#define _POSIX_C_SOURCE 200809L  // for strnlen

#include "validate.h"

#include <string.h>

ValidateStatus validate_absolute_path(const char *path) {
    if (path == nullptr || path[0] == '\0') return VALIDATE_ERR_EMPTY;
    if (path[0] != '/') return VALIDATE_ERR_NOT_ABSOLUTE;

    // strnlen never reads more than VALIDATE_PATH_MAX bytes.
    const size_t len = strnlen(path, VALIDATE_PATH_MAX);
    if (len >= VALIDATE_PATH_MAX) return VALIDATE_ERR_TOO_LONG;
    if (path[len - 1] == '/') return VALIDATE_ERR_NOT_A_FILE;

    // Prevent directory traversal (e.g., "../" or trailing "..")
    if (strstr(path, "/../") != nullptr || strstr(path, "/./") != nullptr ||
        (len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
        (len >= 2 && strcmp(path + len - 2, "/.") == 0)) {
        return VALIDATE_ERR_TRAVERSAL;
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
        case VALIDATE_ERR_TRAVERSAL: return "path contains traversal components (.. or .)";
    }
    return "unknown error";
}