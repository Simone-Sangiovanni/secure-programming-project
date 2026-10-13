#ifndef SFM_CONFIG_H
#define SFM_CONFIG_H

/**
 * @file config.h
 * @brief Loading, saving and inspecting the application configuration.
 *
 * The configuration is stored on disk as a small JSON file holding the KDF
 * name, the salt and verifier (Base64) used for the master password, and the
 * paths of the vault and log files.
 */

/** In-memory representation of the configuration file. */
typedef struct {
    char kdf[32];         /**< Name of the key derivation function. */
    char salt[64];        /**< 16 bytes of salt encoded in Base64. */
    char verifier[128];   /**< 32 bytes of verifier encoded in Base64. */
    char vault_path[512]; /**< Path of the encrypted vault. */
    char log_path[512];   /**< Path of the log file. */
    char config_path[512];/**< Path this config was loaded from / saves to. */
} SfmConfig;

/** Result codes returned by every config function. */
typedef enum {
    CONFIG_OK = 0,         /**< Success. */
    CONFIG_ERR_ARGS,       /**< NULL pointer passed by the caller (a bug). */
    CONFIG_ERR_NOT_FOUND,  /**< Config file does not exist (normal on first run). */
    CONFIG_ERR_IO,         /**< Open/read/write/allocation failure. */
    CONFIG_ERR_PARSE,      /**< File exists but is not valid JSON. */
    CONFIG_ERR_INVALID     /**< File too big, or a value does not fit its field. */
} ConfigStatus;

/**
 * @brief Loads the configuration file into memory.
 *
 * Missing or non-string JSON keys become empty strings. @p cfg is modified
 * only when the function returns CONFIG_OK, so a failed load never leaves a
 * half-filled struct behind.
 *
 * @param file_path Path of the JSON config file to read.
 * @param cfg       Output struct to fill. Must not be NULL.
 * @return CONFIG_OK on success; CONFIG_ERR_NOT_FOUND if the file does not
 *         exist; CONFIG_ERR_PARSE / CONFIG_ERR_INVALID / CONFIG_ERR_IO /
 *         CONFIG_ERR_ARGS otherwise.
 */
[[nodiscard]] ConfigStatus load_config(const char *file_path, SfmConfig *cfg);

/**
 * @brief Writes the configuration to disk as JSON.
 *
 * Overwrites @p file_path if it already exists.
 *
 * @param file_path Destination path.
 * @param cfg       Configuration to write. Must not be NULL.
 * @return CONFIG_OK on success, CONFIG_ERR_IO if the file could not be fully
 *         written, CONFIG_ERR_ARGS if a pointer is NULL.
 */
[[nodiscard]] ConfigStatus save_config(const char *file_path, const SfmConfig *cfg);

/**
 * @brief Fills @p cfg with default values and no master password.
 *
 * Intended for the case where no config file exists yet. The resulting
 * struct has an empty salt and verifier, so config_is_first_run() returns
 * true for it.
 *
 * @param cfg         Struct to initialise. Must not be NULL.
 * @param config_path Path the config will be saved to. Must not be NULL.
 * @return CONFIG_OK on success, CONFIG_ERR_INVALID if @p config_path does not
 *         fit in the struct, CONFIG_ERR_ARGS if a pointer is NULL.
 */
[[nodiscard]] ConfigStatus config_set_defaults(SfmConfig *cfg, const char *config_path);

/**
 * @brief Tells whether the program has no master password set up yet.
 *
 * @param cfg Loaded configuration.
 * @return true if the salt or the verifier is empty (or @p cfg is NULL),
 *         false if both are present.
 */
[[nodiscard]] bool config_is_first_run(const SfmConfig *cfg);

#endif