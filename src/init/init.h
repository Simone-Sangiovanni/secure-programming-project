#ifndef SFM_INIT_H
#define SFM_INIT_H

#include <stddef.h>

/**
 * @file init.h
 * @brief First-run initialisation of the files and folders sfm uses.
 *
 * Layout created in the home directory of the user running sfm:
 *
 *   ~/.config/sfm/config.json        configuration file         (0600)
 *   ~/.local/state/sfm/sfm.log       log file                   (0600)
 *   ~/.local/share/sfm/vault/        vault folder               (0700)
 *
 * Every folder named "sfm" (and "vault") is created with mode 0700 and
 * every file with mode 0600, so only the owner can read, write or enter them.
 *
 * Everything is created by the sfm process itself, running with the user's
 * own privileges, so it automatically belongs to the user. For the same
 * reason sfm refuses to run as root: a root process creating files inside a
 * user's home would leave them owned by root.
 *
 * Running init again is safe: what exists is checked (and its permissions
 * are tightened if needed), what is missing is created.
 */

/** Size of the path buffers (same as the path fields of SfmConfig). */
#define INIT_PATH_MAX 512

/** The locations sfm uses. All are absolute paths. */
typedef struct {
    char config_file[INIT_PATH_MAX];  /**< ~/.config/sfm/config.json */
    char log_file[INIT_PATH_MAX];     /**< ~/.local/state/sfm/sfm.log */
    char vault_dir[INIT_PATH_MAX];    /**< ~/.local/share/sfm/vault */
} SfmPaths;

/** Result codes returned by init_setup(). */
typedef enum {
    INIT_OK = 0,             /**< Everything exists with the right permissions. */
    INIT_ERR_ARGS,           /**< NULL pointer passed by the caller (a bug). */
    INIT_ERR_ROOT,           /**< Running as root: refused. */
    INIT_ERR_NO_HOME,        /**< The home directory could not be determined. */
    INIT_ERR_BAD_HOME,       /**< The home directory is not an absolute path to a directory. */
    INIT_ERR_PATH_TOO_LONG,  /**< A path does not fit in INIT_PATH_MAX. */
    INIT_ERR_MKDIR,          /**< A folder could not be created. */
    INIT_ERR_ACCESS,         /**< A folder or file could not be opened. */
    INIT_ERR_NOT_DIR,        /**< Expected a real folder, found something else (e.g. a symlink). */
    INIT_ERR_NOT_FILE,       /**< Expected a regular file, found something else (symlink, folder, ...). */
    INIT_ERR_OWNER,          /**< Exists but belongs to another user. */
    INIT_ERR_PERMS,          /**< The required permissions could not be applied. */
    INIT_ERR_CREATE,         /**< A file could not be created. */
    INIT_ERR_CONFIG          /**< The default configuration could not be written. */
} InitStatus;

/**
 * @brief Creates (or verifies) the whole layout and reports where it is.
 *
 * Steps: refuse root -> find the home directory ($HOME, or the password
 * database if unset) -> create/verify the three locations -> create the
 * default configuration if config.json does not exist yet.
 *
 * Folders are walked with file descriptors (openat/mkdirat) and symbolic
 * links are refused for sfm's own folders and files, so a link planted by
 * someone else cannot redirect sfm to another place.
 *
 * The standard parent folders (~/.config, ~/.local/state, ~/.local/share) are
 * created with mode 0700 if missing, but if they already exist they are left
 * exactly as they are (they belong to the user's other programs, and
 * ~/.config is often a symlink to a dotfiles repository).
 *
 * @param paths Receives the absolute paths on success (untouched on failure).
 * @return INIT_OK or the reason it failed.
 */
[[nodiscard]] InitStatus init_setup(SfmPaths *paths);

/** Returns a human-readable message for an InitStatus (never NULL). */
[[nodiscard]] const char *init_strerror(InitStatus status);

#endif