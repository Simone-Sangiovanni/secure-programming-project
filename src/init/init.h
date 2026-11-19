#ifndef SFM_INIT_H
#define SFM_INIT_H

#include <stddef.h>
#include "../config/config.h"

/**
 * @file init.h
 * @brief Initialisation and recovery of the files and folders sfm uses.
 *
 * Default layout created in the home directory of the user running sfm:
 *
 *   ~/.config/sfm/sfm.config         configuration file         (0600)
 *   ~/.local/state/sfm/sfm.log       log file                   (0600)
 *   ~/.local/share/sfm/vault/        vault folder               (0700)
 *
 * Every folder belonging to sfm is created with mode 0700 and every file with
 * mode 0600, so only the owner can read, write or enter them.
 *
 * Startup runs in two stages so custom paths stored in sfm.config are honoured:
 *   1. init_prepare_config() ensures ~/.config/sfm/sfm.config exists (writing
 *      the default configuration if missing) and verifies its owner and 0600
 *      permissions without touching the vault or log yet.
 *   2. After load_config() parses sfm.config, init_ensure_storage() creates or
 *      verifies the vault directory and log file at the exact paths configured
 *      in sfm.config (recreating them if either was deleted).
 */

/** Size of the path buffers (same as the path fields of SfmConfig). */
#define INIT_PATH_MAX 512

/** The default locations sfm uses. All are absolute paths. */
typedef struct {
    char config_file[INIT_PATH_MAX];  /**< ~/.config/sfm/sfm.config */
    char log_file[INIT_PATH_MAX];     /**< ~/.local/state/sfm/sfm.log */
    char vault_dir[INIT_PATH_MAX];    /**< ~/.local/share/sfm/vault */
} SfmPaths;

/** Result codes returned by init functions. */
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
 * @brief Ensures the configuration folder (~/.config/sfm) and configuration
 *        file (~/.config/sfm/sfm.config) exist with valid ownership and
 *        permissions (0700 folder, 0600 file).
 *
 * If sfm.config does not exist yet, writes the default configuration using the
 * user's default XDG paths. Does not create or modify the vault or log file;
 * call init_ensure_storage() after load_config() so configured paths are used.
 *
 * @param paths Receives the resolved default paths on success.
 * @return INIT_OK or the reason it failed.
 */
[[nodiscard]] InitStatus init_prepare_config(SfmPaths *paths);

/**
 * @brief Recreates or verifies the vault directory and log file specified in
 *        the loaded configuration @p cfg.
 *
 * Walks directory components with openat/mkdirat, refuses symlinks on sfm's
 * own folders and files (O_NOFOLLOW), verifies owner UID == geteuid(), and
 * enforces mode 0700 on sfm directories and mode 0600 on the log file.
 *
 * @param cfg Loaded configuration containing vault_path and log_path.
 * @return INIT_OK or the reason it failed.
 */
[[nodiscard]] InitStatus init_ensure_storage(const SfmConfig *cfg);

/**
 * @brief Convenience wrapper that prepares sfm.config, loads it, and ensures
 *        the configured vault and log storage exist.
 *
 * @param paths Receives the resolved default paths on success.
 * @return INIT_OK or the reason it failed.
 */
[[nodiscard]] InitStatus init_setup(SfmPaths *paths);

/** Returns a human-readable message for an InitStatus (never NULL). */
[[nodiscard]] const char *init_strerror(InitStatus status);

#endif