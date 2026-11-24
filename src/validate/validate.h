#ifndef SFM_VALIDATE_H
#define SFM_VALIDATE_H

/**
 * @file validate.h
 * @brief First-level validation of user input (file and directory paths).
 */

/** Longest accepted path in bytes, including the terminating '\0'. */
#define VALIDATE_PATH_MAX 4096

/** Result codes of the validation functions. */
typedef enum {
    VALIDATE_OK = 0,           /**< The input is acceptable. */
    VALIDATE_ERR_EMPTY,        /**< NULL or empty string. */
    VALIDATE_ERR_NOT_ABSOLUTE, /**< Does not start with '/'. */
    VALIDATE_ERR_TOO_LONG,     /**< Longer than VALIDATE_PATH_MAX - 1 bytes. */
    VALIDATE_ERR_NOT_A_FILE,   /**< Ends with '/', so it names a directory. */
    VALIDATE_ERR_TRAVERSAL,    /**< Path contains traversal components (.. or .). */
    VALIDATE_ERR_NOT_A_DIR,    /**< Directory does not exist or is not a directory. */
    VALIDATE_ERR_PARENT        /**< The parent directory of a file path does not exist or is not a directory. */
} ValidateStatus;

/**
 * @brief Checks that @p path is a usable absolute file path.
 *
 * Only the text of the path is checked; whether the file exists is decided
 * later, when it is opened.
 *
 * @param path Path typed by the user.
 * @return VALIDATE_OK or the reason it was rejected.
 */
[[nodiscard]] ValidateStatus validate_absolute_path(const char *path);

/**
 * @brief Checks that @p path is a usable absolute file path and canonicalizes
 *        its PARENT directory (realpath), so symbolic links in the directory
 *        part are resolved before the file is used.
 *
 * The final component (the file itself) is deliberately NOT resolved: it is
 * opened later with O_NOFOLLOW, so a symlink named as the file is refused.
 * The file does not have to exist.
 *
 * @param path         File path typed by the user.
 * @param resolved_out Buffer receiving "<canonical parent>/<file name>".
 * @return VALIDATE_OK or the reason it was rejected.
 */
[[nodiscard]] ValidateStatus validate_file_path(const char *path,
                                                char resolved_out[VALIDATE_PATH_MAX]);

/**
 * @brief Checks that @p path is an existing absolute directory path and
 *        resolves its canonical path into @p resolved_out.
 *
 * Does not require the caller to own the directory so shared folders such as
 * /tmp can be used as decryption destinations.
 *
 * @param path         Directory path typed by the user.
 * @param resolved_out Optional buffer receiving the canonical path.
 * @return VALIDATE_OK or the reason it was rejected.
 */
[[nodiscard]] ValidateStatus validate_directory_path(const char *path,
                                                     char resolved_out[VALIDATE_PATH_MAX]);

/** Returns a human-readable message for a ValidateStatus (never NULL). */
[[nodiscard]] const char *validate_strerror(ValidateStatus status);

#endif
