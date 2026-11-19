#ifndef SFM_AUTH_H
#define SFM_AUTH_H

#include "../config/config.h"

/**
 * @file auth.h
 * @brief Master password setup (first run) and login, using libsodium.
 *
 * Scheme:
 *   - salt     = 16 random bytes
 *   - master   = Argon2id(password, salt)                        (32 bytes)
 *   - verifier = HKDF-SHA256(master, salt, "sfm-verifier-v1")    (32 bytes)
 *   - KEK      = HKDF-SHA256(master, salt, "sfm-kek-v1")         (32 bytes)
 *
 * The salt and the verifier (both Base64) are stored in the config file.
 * The verifier and the Key-Encryption Key (KEK) are derived from the master
 * key via RFC 5869 HKDF-SHA256 with distinct domain-separation info labels,
 * so knowing the verifier (which sits on disk) does not reveal the KEK used
 * to wrap per-file Data-Encryption Keys (DEKs). Sensitive buffers are locked
 * in RAM with sodium_mlock(), registered with the termination signal handler,
 * and wiped with sodium_memzero() / sodium_munlock() immediately after use.
 */

#define AUTH_PASSWORD_MAX 66
#define AUTH_KEY_BYTES 32

typedef enum {
    AUTH_OK = 0,
    AUTH_ERR_ARGS,
    AUTH_ERR_IO,
    AUTH_ERR_TOO_LONG,
    AUTH_ERR_EMPTY,
    AUTH_ERR_WEAK,
    AUTH_ERR_MISMATCH,
    AUTH_ERR_CRYPTO,
    AUTH_ERR_CONFIG,
    AUTH_ERR_SAVE,
    AUTH_ERR_WRONG_PASSWORD
} AuthStatus;

[[nodiscard]] AuthStatus auth_setup_master_password(SfmConfig *cfg, unsigned char key_out[AUTH_KEY_BYTES]);
[[nodiscard]] AuthStatus auth_login(const SfmConfig *cfg, unsigned char *key_out);
[[nodiscard]] const char *auth_strerror(AuthStatus status);

#endif