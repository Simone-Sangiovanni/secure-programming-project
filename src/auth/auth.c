#include "auth.h"
#include "../cli/cli.h"
#include <assert.h>
#include <ctype.h>
#include <sodium.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define AUTH_SALT_BYTES crypto_pwhash_SALTBYTES
#define AUTH_MASTER_BYTES 32
#define AUTH_VERIFIER_BYTES 32
#define AUTH_B64_VARIANT sodium_base64_VARIANT_ORIGINAL
#define AUTH_KDF_NAME "argon2id"
#define AUTH_BACKOFF_MAX_SEC 30U

#define HKDF_INFO_VERIFIER "sfm-verifier-v1"
#define HKDF_INFO_KEK      "sfm-kek-v1"

#define AUTH_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define AUTH_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

static_assert(sodium_base64_ENCODED_LEN(AUTH_SALT_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->salt), "config.salt too small for a Base64 salt");
static_assert(sodium_base64_ENCODED_LEN(AUTH_VERIFIER_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->verifier), "config.verifier too small for Base64 verifier");
static_assert(sizeof(((SfmConfig *)nullptr)->kdf) >= sizeof(AUTH_KDF_NAME), "config.kdf too small");
static_assert(AUTH_VERIFIER_BYTES == crypto_auth_hmacsha256_BYTES, "verifier size mismatch");
static_assert(AUTH_KEY_BYTES == crypto_auth_hmacsha256_BYTES, "KEK size mismatch");

/* ---------- helpers (private to this file) ---------- */

static bool init_sodium(void) {
    return sodium_init() >= 0;
}

static void wipe_and_unlock(void *buf, size_t size) {
    cli_unregister_secret(buf);
    sodium_memzero(buf, size);
    (void)sodium_munlock(buf, size);
}

static AuthStatus read_password(const char *prompt, char *buff, size_t size) {
    struct termios old_settings;
    if (tcgetattr(STDIN_FILENO, &old_settings) != 0) return AUTH_ERR_IO;

    struct termios no_echo = old_settings;
    no_echo.c_lflag &= ~(tcflag_t)ECHO;

    cli_register_termios(&old_settings);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo) != 0) {
        cli_unregister_termios();
        return AUTH_ERR_IO;
    }

    (void)fputs(prompt, stderr);
    (void)fflush(stderr);

    AuthStatus status = AUTH_OK;
    if (fgets(buff, (int)size, stdin) == nullptr) {
        status = AUTH_ERR_IO;
    } else {
        const size_t len = strcspn(buff, "\n");
        if (buff[len] == '\n') {
            buff[len] = '\0';
        } else {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { /* discard */ }
            status = AUTH_ERR_TOO_LONG;
        }
    }

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings) != 0 && status == AUTH_OK) {
        status = AUTH_ERR_IO;
    }
    cli_unregister_termios();

    (void)fputc('\n', stderr);
    if (status != AUTH_OK) sodium_memzero(buff, size);
    return status;
}

/**
 * @brief Derives a 32-byte subkey using RFC 5869 HKDF-SHA256 (Extract + Expand)
 *        implemented over libsodium's audited HMAC-SHA256 primitive.
 */
static int hkdf_sha256_derive(unsigned char out[crypto_auth_hmacsha256_BYTES],
                              const unsigned char *ikm, size_t ikm_len,
                              const unsigned char *salt, size_t salt_len,
                              const char *info) {
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    if (sodium_mlock(prk, sizeof prk) != 0) {
        return -1;
    }
    cli_register_secret(prk, sizeof prk);

    const unsigned char zero_salt[crypto_auth_hmacsha256_BYTES] = {};
    const unsigned char *actual_salt = (salt != nullptr && salt_len > 0) ? salt : zero_salt;
    const size_t actual_salt_len = (salt != nullptr && salt_len > 0) ? salt_len : sizeof zero_salt;

    // 1. HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    crypto_auth_hmacsha256_state hmac;
    if (crypto_auth_hmacsha256_init(&hmac, actual_salt, actual_salt_len) != 0 ||
        crypto_auth_hmacsha256_update(&hmac, ikm, ikm_len) != 0 ||
        crypto_auth_hmacsha256_final(&hmac, prk) != 0) {
        sodium_memzero(&hmac, sizeof hmac);
        wipe_and_unlock(prk, sizeof prk);
        return -1;
    }

    // 2. HKDF-Expand (single 32-byte block): OKM = HMAC-SHA256(PRK, info || 0x01)
    const unsigned char counter = 0x01U;
    if (crypto_auth_hmacsha256_init(&hmac, prk, sizeof prk) != 0 ||
        crypto_auth_hmacsha256_update(&hmac, (const unsigned char *)info, strlen(info)) != 0 ||
        crypto_auth_hmacsha256_update(&hmac, &counter, 1U) != 0 ||
        crypto_auth_hmacsha256_final(&hmac, out) != 0) {
        sodium_memzero(&hmac, sizeof hmac);
        wipe_and_unlock(prk, sizeof prk);
        return -1;
    }

    sodium_memzero(&hmac, sizeof hmac);
    wipe_and_unlock(prk, sizeof prk);
    return 0;
}

static int derive_keys(const char *password, const unsigned char salt[AUTH_SALT_BYTES],
                       unsigned char verifier_out[AUTH_VERIFIER_BYTES],
                       unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char master[AUTH_MASTER_BYTES];
    if (sodium_mlock(master, sizeof master) != 0) {
        return -1;
    }
    cli_register_secret(master, sizeof master);

    int rc = crypto_pwhash(master, sizeof master, password, strlen(password),
                           salt, AUTH_OPSLIMIT, AUTH_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);

    if (rc == 0) {
        rc = hkdf_sha256_derive(verifier_out, master, sizeof master,
                                salt, AUTH_SALT_BYTES, HKDF_INFO_VERIFIER);
    }
    if (rc == 0) {
        rc = hkdf_sha256_derive(key_out, master, sizeof master,
                                salt, AUTH_SALT_BYTES, HKDF_INFO_KEK);
    }

    wipe_and_unlock(master, sizeof master);
    return rc == 0 ? 0 : -1;
}

static bool decode_b64(const char *b64, unsigned char *out, size_t expected) {
    size_t decoded = 0;
    if (sodium_base642bin(out, expected, b64, strlen(b64), nullptr, &decoded,
                          nullptr, AUTH_B64_VARIANT) != 0) {
        return false;
    }
    return decoded == expected;
}

static AuthStatus create_credentials(const char *password, SfmConfig *cfg,
                                     unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char verifier[AUTH_VERIFIER_BYTES];
    unsigned char key[AUTH_KEY_BYTES];

    if (sodium_mlock(salt, sizeof salt) != 0) {
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(salt, sizeof salt);

    if (sodium_mlock(verifier, sizeof verifier) != 0) {
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(verifier, sizeof verifier);

    if (sodium_mlock(key, sizeof key) != 0) {
        wipe_and_unlock(verifier, sizeof verifier);
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(key, sizeof key);

    AuthStatus status = AUTH_ERR_CRYPTO;
    randombytes_buf(salt, sizeof salt);

    if (derive_keys(password, salt, verifier, key) == 0 &&
        sodium_bin2base64(cfg->salt, sizeof cfg->salt, salt, sizeof salt, AUTH_B64_VARIANT) != nullptr &&
        sodium_bin2base64(cfg->verifier, sizeof cfg->verifier, verifier, sizeof verifier, AUTH_B64_VARIANT) != nullptr) {
        memcpy(cfg->kdf, AUTH_KDF_NAME, sizeof AUTH_KDF_NAME);
        memcpy(key_out, key, sizeof key);
        status = AUTH_OK;
    }

    wipe_and_unlock(salt, sizeof salt);
    wipe_and_unlock(verifier, sizeof verifier);
    wipe_and_unlock(key, sizeof key);
    return status;
}

static bool is_password_complex(const char *password) {
    const size_t len = strlen(password);
    if (len < 8 || len > 64) return false;

    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_special = false;

    for (size_t i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)password[i];
        if (isupper(ch)) has_upper = true;
        else if (islower(ch)) has_lower = true;
        else if (isdigit(ch)) has_digit = true;
        else has_special = true;
    }

    return has_upper && has_lower && has_digit && has_special;
}

/* ---------- public API ---------- */

AuthStatus auth_setup_master_password(SfmConfig *cfg, unsigned char key_out[AUTH_KEY_BYTES]) {
    if (cfg == nullptr || key_out == nullptr || cfg->config_path[0] == '\0') {
        return AUTH_ERR_ARGS;
    }
    if (!init_sodium()) return AUTH_ERR_CRYPTO;

    char password[AUTH_PASSWORD_MAX];
    char confirm[AUTH_PASSWORD_MAX];
    unsigned char key[AUTH_KEY_BYTES];

    if (sodium_mlock(password, sizeof password) != 0) {
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(password, sizeof password);

    if (sodium_mlock(confirm, sizeof confirm) != 0) {
        wipe_and_unlock(password, sizeof password);
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(confirm, sizeof confirm);

    if (sodium_mlock(key, sizeof key) != 0) {
        wipe_and_unlock(confirm, sizeof confirm);
        wipe_and_unlock(password, sizeof password);
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(key, sizeof key);

    AuthStatus status = read_password("Choose a master password: ", password, sizeof password);

    if (status == AUTH_OK && password[0] == '\0') {
        status = AUTH_ERR_EMPTY;
    } else if (status == AUTH_OK && !is_password_complex(password)) {
        status = AUTH_ERR_WEAK;
    }

    if (status == AUTH_OK) {
        status = read_password("Confirm master password: ", confirm, sizeof confirm);
        if (status == AUTH_OK && strcmp(password, confirm) != 0) {
            status = AUTH_ERR_MISMATCH;
        }
    }

    if (status == AUTH_OK) {
        printf("Generating keys (this takes a moment)...\n");
        SfmConfig updated = *cfg;
        status = create_credentials(password, &updated, key);
        if (status == AUTH_OK) {
            if (save_config(updated.config_path, &updated) == CONFIG_OK) {
                *cfg = updated;
                memcpy(key_out, key, sizeof key);
            } else {
                status = AUTH_ERR_SAVE;
            }
        }
    }

    wipe_and_unlock(password, sizeof password);
    wipe_and_unlock(confirm, sizeof confirm);
    wipe_and_unlock(key, sizeof key);

    return status;
}

AuthStatus auth_login(const SfmConfig *cfg, unsigned char *key_out) {
    if (cfg == nullptr || key_out == nullptr) return AUTH_ERR_ARGS;
    if (!init_sodium()) return AUTH_ERR_CRYPTO;
    if (config_is_first_run(cfg)) return AUTH_ERR_CONFIG;

    if (strcmp(cfg->kdf, AUTH_KDF_NAME) != 0) {
        return AUTH_ERR_CONFIG;
    }

    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char stored[AUTH_VERIFIER_BYTES];

    if (sodium_mlock(salt, sizeof salt) != 0) {
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(salt, sizeof salt);

    if (sodium_mlock(stored, sizeof stored) != 0) {
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CRYPTO;
    }
    cli_register_secret(stored, sizeof stored);

    if (!decode_b64(cfg->salt, salt, sizeof salt) ||
        !decode_b64(cfg->verifier, stored, sizeof stored)) {
        wipe_and_unlock(stored, sizeof stored);
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CONFIG;
    }

    AuthStatus status = AUTH_ERR_WRONG_PASSWORD;
    unsigned int backoff_sec = 1U;

    while (true) {
        char password[AUTH_PASSWORD_MAX];
        unsigned char verifier[AUTH_VERIFIER_BYTES];
        unsigned char key[AUTH_KEY_BYTES];

        if (sodium_mlock(password, sizeof password) != 0) {
            status = AUTH_ERR_CRYPTO;
            break;
        }
        cli_register_secret(password, sizeof password);

        if (sodium_mlock(verifier, sizeof verifier) != 0) {
            wipe_and_unlock(password, sizeof password);
            status = AUTH_ERR_CRYPTO;
            break;
        }
        cli_register_secret(verifier, sizeof verifier);

        if (sodium_mlock(key, sizeof key) != 0) {
            wipe_and_unlock(verifier, sizeof verifier);
            wipe_and_unlock(password, sizeof password);
            status = AUTH_ERR_CRYPTO;
            break;
        }
        cli_register_secret(key, sizeof key);

        const AuthStatus rs = read_password("Master password: ", password, sizeof password);
        if (rs != AUTH_OK) {
            wipe_and_unlock(key, sizeof key);
            wipe_and_unlock(verifier, sizeof verifier);
            wipe_and_unlock(password, sizeof password);
            status = rs;
            break;
        }

        const int rc = derive_keys(password, salt, verifier, key);
        wipe_and_unlock(password, sizeof password);

        if (rc != 0) {
            status = AUTH_ERR_CRYPTO;
        } else if (sodium_memcmp(verifier, stored, sizeof stored) == 0) {
            memcpy(key_out, key, sizeof key);
            status = AUTH_OK;
        } else {
            status = AUTH_ERR_WRONG_PASSWORD;
        }

        wipe_and_unlock(verifier, sizeof verifier);
        wipe_and_unlock(key, sizeof key);

        if (status != AUTH_ERR_WRONG_PASSWORD) break;

        (void)fprintf(stderr, "Wrong password. Waiting %u second%s before next attempt...\n",
                      backoff_sec, (backoff_sec == 1U) ? "" : "s");
        (void)sleep(backoff_sec);
        backoff_sec = (backoff_sec <= (AUTH_BACKOFF_MAX_SEC / 2U)) ? (backoff_sec * 2U) : AUTH_BACKOFF_MAX_SEC;
    }

    wipe_and_unlock(salt, sizeof salt);
    wipe_and_unlock(stored, sizeof stored);
    return status;
}

const char *auth_strerror(AuthStatus status) {
    switch (status) {
        case AUTH_OK: return "Success";
        case AUTH_ERR_ARGS: return "Invalid arguments (internal error)";
        case AUTH_ERR_IO: return "Cannot read the password (is stdin a terminal?)";
        case AUTH_ERR_TOO_LONG: return "Password too long (max 64 characters)";
        case AUTH_ERR_EMPTY: return "Password cannot be empty";
        case AUTH_ERR_WEAK: return "Password must be 8-64 characters long and include an uppercase letter, lowercase letter, number, and special character";
        case AUTH_ERR_MISMATCH: return "Passwords do not match";
        case AUTH_ERR_CRYPTO: return "Cryptographic error";
        case AUTH_ERR_CONFIG: return "Configuration is missing or corrupt";
        case AUTH_ERR_SAVE: return "Could not save the configuration";
        case AUTH_ERR_WRONG_PASSWORD: return "Wrong password";
    }
    return "Unknown error";
}