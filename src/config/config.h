#ifndef SFM_CONFIG_H
#define SFM_CONFIG_H

/**
 * @file config.h
 * @brief Loading, saving, and inspecting the SFM JSON configuration.
 */

/** In-memory representation of ~/.config/sfm/sfm.config. */
typedef struct {
    char kdf[32];          /**< Key derivation function name (e.g. "argon2id"). */
    char salt[64];         /**< Base64-encoded 16-byte master password salt. */
    char verifier[128];    /**< Base64-encoded 32-byte master password verifier. */
    char vault_path[512];  /**< Encrypted vault directory path. */
    char log_path[512];    /**< Audit log file path. */
    char config_path[512]; /**< Path this configuration file lives at. */
} SfmConfig;

/** Status codes returned by configuration functions. */
typedef enum {
    CONFIG_OK = 0,        /**< Operation succeeded. */
    CONFIG_ERR_ARGS,      /**< NULL pointer passed by caller. */
    CONFIG_ERR_NOT_FOUND, /**< Configuration file does not exist yet. */
    CONFIG_ERR_IO,        /**< File open, read, write, sync, or allocation failure. */
    CONFIG_ERR_PARSE,     /**< Invalid JSON or inconsistent credential fields. */
    CONFIG_ERR_INVALID    /**< File too large, field too long, or invalid path. */
} ConfigStatus;

/**
 * @brief Loads and validates a JSON configuration file into @p cfg.
 *
 * Modifies @p cfg only if CONFIG_OK is returned.
 */
[[nodiscard]] ConfigStatus load_config(const char *file_path, SfmConfig *cfg);

/**
 * @brief Atomically writes @p cfg as JSON to @p file_path (mode 0600, fsync + rename).
 */
[[nodiscard]] ConfigStatus save_config(const char *file_path, const SfmConfig *cfg);

/**
 * @brief Initializes @p cfg with default KDF ("argon2id"), paths, and empty credentials.
 */
[[nodiscard]] ConfigStatus config_set_defaults(SfmConfig *cfg, const char *config_path,
                                               const char *vault_path, const char *log_path);

/**
 * @brief Returns true if @p cfg is NULL or has no master password configured yet.
 */
[[nodiscard]] bool config_is_first_run(const SfmConfig *cfg);

#endif
