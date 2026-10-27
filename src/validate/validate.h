#ifndef SFM_VALIDATE_H
#define SFM_VALIDATE_H

/**
 * @file validate.h
 * @brief First-level validation of user input (paths for now).
 *
 * Every check lives here, so hardening it later (symlinks, "..", allowed
 * directories, ...) does not require touching the callers.
 */

/** Longest accepted path in bytes, including the terminating '\0'. */
#define VALIDATE_PATH_MAX 4096

/** Result codes of the validation functions. */
typedef enum {
    VALIDATE_OK = 0,           /**< The input is acceptable. */
    VALIDATE_ERR_EMPTY,        /**< NULL or empty string. */
    VALIDATE_ERR_NOT_ABSOLUTE, /**< Does not start with '/'. */
    VALIDATE_ERR_TOO_LONG,     /**< Longer than VALIDATE_PATH_MAX - 1 bytes. */
    VALIDATE_ERR_NOT_A_FILE    /**< Ends with '/', so it names a directory. */
} ValidateStatus;

/**
 * @brief Checks that @p path is a usable absolute file path.
 *
 * Only the text of the path is checked; whether the file exists is decided
 * later, when it is opened.
 *
 * TODO(security): reject ".." components, resolve symlinks (realpath) and
 *                 restrict to allowed directories (checkpoint 3).
 *
 * @param path Path typed by the user.
 * @return VALIDATE_OK or the reason it was rejected.
 */
[[nodiscard]] ValidateStatus validate_absolute_path(const char *path);

/** Returns a human-readable message for a ValidateStatus (never NULL). */
[[nodiscard]] const char *validate_strerror(ValidateStatus status);

#endif