#ifndef SFM_AUTH_H
#define SFM_AUTH_H

#include "../config/config.h"

/**
 * @file auth.h
 * @brief Master password setup (first run) and login, using libsodium.
 *
 * Scheme:
 *   - salt     = 16 random bytes
 *   - master   = Argon2id(password, salt)                  (32 bytes)
 *   - verifier = KDF(master, id 1, context "sfmverif")     (32 bytes)
 *   - file key = KDF(master, id 2, context "sfmfkey!")     (32 bytes)
 *
 * The salt and the verifier (both Base64) are stored in the config file.
 * The verifier and the file key are derived from the master key with
 * different KDF contexts, so knowing the verifier (which sits on disk) does
 * not reveal the key used to encrypt files. The password itself is never
 * stored.
 */

// max password lenght
#define AUTH_PASSWORD_MAX 128

// size in bytes of the file-encryption key returned by setup / login
#define AUTH_KEY_BYTES 32

// Number of password attempts allowed by auth_login()
#define AUTH_MAX_ATTEMPTS 5

// result codes returned by the auth functions
typedef enum {
    AUTH_OK = 0,           /**< Success. */
    AUTH_ERR_ARGS,         /**< NULL pointer or unusable argument (a bug). */
    AUTH_ERR_IO,           /**< Terminal could not be read or configured. */
    AUTH_ERR_TOO_LONG,     /**< Password longer than AUTH_PASSWORD_MAX - 1. */
    AUTH_ERR_EMPTY,        /**< User entered an empty password. */
    AUTH_ERR_MISMATCH,     /**< The two entries did not match. */
    AUTH_ERR_CRYPTO,       /**< libsodium failure (init, out of memory, ...). */
    AUTH_ERR_CONFIG,       /**< Salt/verifier in the config are missing or corrupt. */
    AUTH_ERR_SAVE,         /**< The config file could not be written. */
    AUTH_ERR_WRONG_PASSWORD/**< All login attempts failed. */
} AuthStatus;

/**
 * @brief Creates the master password: asks for it, generates the salt and
 *        the verifier, and saves them in the config file.
 *
 * Prompts twice (typed characters are not shown), checks that both entries
 * match, then derives the keys with Argon2id and writes salt, verifier and
 * kdf name to the file at cfg->config_path. @p cfg is modified only if the
 * whole operation, including the save, succeeded.
 *
 * @param cfg     Configuration to update. Must have a non-empty config_path.
 * @param key_out Receives the AUTH_KEY_BYTES-byte file-encryption key. The
 *                caller must wipe it with sodium_memzero() when done.
 * @return AUTH_OK on success, otherwise the reason it failed.
 */
[[nodiscard]] AuthStatus auth_setup_master_password(SfmConfig *cfg, unsigned char key_out[AUTH_KEY_BYTES]);

/**
 * @brief Logs in: asks for the master password and checks it against the
 *        verifier stored in the config.
 *
 * Allows up to AUTH_MAX_ATTEMPTS tries. The comparison is constant-time.
 *
 * @param cfg     Loaded configuration containing salt and verifier.
 * @param key_out Receives the AUTH_KEY_BYTES-byte file-encryption key on
 *                success. The caller must wipe it with sodium_memzero().
 * @return AUTH_OK on success, AUTH_ERR_WRONG_PASSWORD after too many wrong
 *         attempts, or another code for other failures.
 */
[[nodiscard]] AuthStatus auth_login(const SfmConfig *cfg, unsigned char *key_out);

/**
 * @brief Returns a human-readable message for an AuthStatus (never NULL).
 */
[[nodiscard]] const char *auth_strerror(AuthStatus status);

#endif