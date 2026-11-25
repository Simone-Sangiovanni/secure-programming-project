#ifndef SFM_INIT_H
#define SFM_INIT_H

#include "../config/config.h"

/**
 * @file init.h
 * @brief Initialisation and recovery of the files and folders used by sfm.
 *
 * Default layout under the user's home directory:
 *   ~/.config/sfm/sfm.config      configuration file  (0600)
 *   ~/.local/state/sfm/sfm.log    log file            (0600)
 *   ~/.local/share/sfm/vault/     vault directory     (0700)
 *
 * Startup runs in two stages so custom paths in sfm.config are honoured:
 *   1. init_prepare_config() ensures ~/.config/sfm/sfm.config exists (writing
 *      the default config if missing) and enforces owner + 0600/0700 modes.
 *   2. After load_config() parses sfm.config, init_ensure_storage() creates or
 *      verifies the configured vault directory and log file.
 */

/** Path buffer size (matches SfmConfig path fields). */
#define INIT_PATH_MAX 512

/** Resolved default absolute paths used by sfm. */
typedef struct {
    char config_file[INIT_PATH_MAX];  /**< ~/.config/sfm/sfm.config */
    char log_file[INIT_PATH_MAX];     /**< ~/.local/state/sfm/sfm.log */
    char vault_dir[INIT_PATH_MAX];    /**< ~/.local/share/sfm/vault */
} SfmPaths;

/** Result codes returned by init functions. */
typedef enum {
    INIT_OK = 0,             /**< Everything exists with valid ownership and permissions. */
    INIT_ERR_ARGS,           /**< NULL pointer passed by the caller. */
    INIT_ERR_ROOT,           /**< Running as root is refused. */
    INIT_ERR_NO_HOME,        /**< Home directory could not be determined. */
    INIT_ERR_BAD_HOME,       /**< Path is not a valid absolute directory path. */
    INIT_ERR_PATH_TOO_LONG,  /**< Path exceeds INIT_PATH_MAX. */
    INIT_ERR_MKDIR,          /**< Directory could not be created. */
    INIT_ERR_ACCESS,         /**< Directory or file could not be opened. */
    INIT_ERR_NOT_DIR,        /**< Expected a real directory, found something else (e.g. symlink). */
    INIT_ERR_NOT_FILE,       /**< Expected a regular file, found something else (e.g. symlink). */
    INIT_ERR_OWNER,          /**< Exists but belongs to another user. */
    INIT_ERR_PERMS,          /**< Required 0700/0600 permissions could not be applied. */
    INIT_ERR_CREATE,         /**< File could not be created. */
    INIT_ERR_CONFIG          /**< Default configuration could not be written or loaded. */
} InitStatus;

/**
 * @brief Ensures ~/.config/sfm (0700) and ~/.config/sfm/sfm.config (0600) exist
 *        with valid ownership, writing the default configuration if missing.
 *
 * @param paths Receives the resolved default paths on success.
 * @return INIT_OK or an error code describing the failure.
 */
[[nodiscard]] InitStatus init_prepare_config(SfmPaths *paths);

/**
 * @brief Recreates or verifies the vault directory (0700) and log file (0600)
 *        specified in @p cfg using symlink-safe descriptor traversal.
 *
 * @param cfg Loaded configuration containing vault_path and log_path.
 * @return INIT_OK or an error code describing the failure.
 */
[[nodiscard]] InitStatus init_ensure_storage(const SfmConfig *cfg);

/**
 * @brief Convenience wrapper that prepares sfm.config, loads it, and ensures
 *        the configured vault and log storage exist.
 *
 * @param paths Receives the resolved default paths on success.
 * @return INIT_OK or an error code describing the failure.
 */
[[nodiscard]] InitStatus init_setup(SfmPaths *paths);

/** Returns a human-readable message for @p status (never NULL). */
[[nodiscard]] const char *init_strerror(InitStatus status);

#endif
