#include "auth.h"
#include "../cli/cli.h"
#include "../log/log.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <sodium.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define AUTH_SALT_BYTES      crypto_pwhash_SALTBYTES
#define AUTH_MASTER_BYTES    32
#define AUTH_VERIFIER_BYTES  32
#define AUTH_B64_VARIANT     sodium_base64_VARIANT_ORIGINAL
#define AUTH_KDF_NAME        "argon2id"
#define AUTH_BACKOFF_MAX_SEC 30U

#define HKDF_INFO_VERIFIER   "sfm-verifier-v1"
#define HKDF_INFO_KEK        "sfm-kek-v1"

#define AUTH_OPSLIMIT        crypto_pwhash_OPSLIMIT_MODERATE
#define AUTH_MEMLIMIT        crypto_pwhash_MEMLIMIT_MODERATE

#define ARRAY_LEN(arr)       (sizeof(arr) / sizeof((arr)[0]))

static_assert(sodium_base64_ENCODED_LEN(AUTH_SALT_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->salt), "config.salt too small for Base64 salt");
static_assert(sodium_base64_ENCODED_LEN(AUTH_VERIFIER_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->verifier), "config.verifier too small for Base64 verifier");
static_assert(sizeof(((SfmConfig *)nullptr)->kdf) >= sizeof(AUTH_KDF_NAME), "config.kdf too small");
static_assert(AUTH_VERIFIER_BYTES == crypto_auth_hmacsha256_BYTES, "verifier size mismatch");
static_assert(AUTH_KEY_BYTES == crypto_auth_hmacsha256_BYTES, "KEK size mismatch");

typedef struct {
    void *ptr;
    size_t size;
} SecretBuf;

/* ---------- secret memory helpers ---------- */

static bool lock_secret(void *buf, size_t size) {
    if (sodium_mlock(buf, size) != 0) return false;
    cli_register_secret(buf, size);
    return true;
}

static void wipe_and_unlock(void *buf, size_t size) {
    cli_unregister_secret(buf);
    sodium_memzero(buf, size);
    (void)sodium_munlock(buf, size);
}

static void unlock_secrets(const SecretBuf *bufs, size_t count) {
    for (size_t i = count; i > 0; i--) {
        wipe_and_unlock(bufs[i - 1].ptr, bufs[i - 1].size);
    }
}

static bool lock_secrets(const SecretBuf *bufs, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!lock_secret(bufs[i].ptr, bufs[i].size)) {
            unlock_secrets(bufs, i);
            return false;
        }
    }
    return true;
}

/* ---------- terminal & validation helpers ---------- */

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

    // Read directly via read(2) into the locked buffer so libc stdio never holds an unwiped copy.
    // Keep up to size - 2 chars (64 for AUTH_PASSWORD_MAX) and drain any extra chars until '\n'.
    AuthStatus status = AUTH_OK;
    size_t len = 0;
    bool too_long = false;

    while (true) {
        char c;
        const ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            status = AUTH_ERR_IO;
            break;
        }
        if (c == '\n') break;

        if (len + 2 < size) {
            buff[len++] = c;
        } else {
            too_long = true;
        }
    }

    buff[len] = '\0';
    if (status == AUTH_OK && too_long) status = AUTH_ERR_TOO_LONG;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings) != 0 && status == AUTH_OK) {
        status = AUTH_ERR_IO;
    }
    cli_unregister_termios();

    (void)fputc('\n', stderr);
    if (status != AUTH_OK) sodium_memzero(buff, size);
    return status;
}

static bool is_password_complex(const char *password) {
    const size_t len = strlen(password);
    if (len < 8 || len > 64) return false;

    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    for (size_t i = 0; i < len; i++) {
        const unsigned char ch = (unsigned char)password[i];
        if (isupper(ch))      has_upper = true;
        else if (islower(ch)) has_lower = true;
        else if (isdigit(ch)) has_digit = true;
        else                  has_special = true;
    }
    return has_upper && has_lower && has_digit && has_special;
}

/* ---------- cryptographic helpers ---------- */

/**
 * @brief Derives a 32-byte subkey using RFC 5869 HKDF-SHA256 (Extract + Expand).
 */
static int hkdf_sha256_derive(unsigned char out[crypto_auth_hmacsha256_BYTES],
                              const unsigned char *ikm, size_t ikm_len,
                              const unsigned char *salt, size_t salt_len,
                              const char *info) {
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    if (!lock_secret(prk, sizeof prk)) return -1;

    const unsigned char zero_salt[crypto_auth_hmacsha256_BYTES] = {};
    const bool has_salt = (salt != nullptr && salt_len > 0);
    const unsigned char *actual_salt = has_salt ? salt : zero_salt;
    const size_t actual_salt_len = has_salt ? salt_len : sizeof zero_salt;

    const unsigned char counter = 0x01U;
    crypto_auth_hmacsha256_state hmac;

    // 1. Extract: PRK = HMAC-SHA256(salt, IKM)
    // 2. Expand:  OKM = HMAC-SHA256(PRK, info || 0x01)
    const bool ok =
        crypto_auth_hmacsha256_init(&hmac, actual_salt, actual_salt_len) == 0 &&
        crypto_auth_hmacsha256_update(&hmac, ikm, ikm_len) == 0 &&
        crypto_auth_hmacsha256_final(&hmac, prk) == 0 &&
        crypto_auth_hmacsha256_init(&hmac, prk, sizeof prk) == 0 &&
        crypto_auth_hmacsha256_update(&hmac, (const unsigned char *)info, strlen(info)) == 0 &&
        crypto_auth_hmacsha256_update(&hmac, &counter, 1U) == 0 &&
        crypto_auth_hmacsha256_final(&hmac, out) == 0;

    sodium_memzero(&hmac, sizeof hmac);
    wipe_and_unlock(prk, sizeof prk);
    return ok ? 0 : -1;
}

static int derive_keys(const char *password, const unsigned char salt[AUTH_SALT_BYTES],
                       unsigned char verifier_out[AUTH_VERIFIER_BYTES],
                       unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char master[AUTH_MASTER_BYTES];
    if (!lock_secret(master, sizeof master)) return -1;

    const bool ok =
        crypto_pwhash(master, sizeof master, password, strlen(password),
                      salt, AUTH_OPSLIMIT, AUTH_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13) == 0 &&
        hkdf_sha256_derive(verifier_out, master, sizeof master,
                           salt, AUTH_SALT_BYTES, HKDF_INFO_VERIFIER) == 0 &&
        hkdf_sha256_derive(key_out, master, sizeof master,
                           salt, AUTH_SALT_BYTES, HKDF_INFO_KEK) == 0;

    wipe_and_unlock(master, sizeof master);
    return ok ? 0 : -1;
}

static bool decode_b64(const char *b64, unsigned char *out, size_t expected) {
    size_t decoded = 0;
    return sodium_base642bin(out, expected, b64, strlen(b64), nullptr, &decoded,
                             nullptr, AUTH_B64_VARIANT) == 0 &&
           decoded == expected;
}

static AuthStatus create_credentials(const char *password, SfmConfig *cfg,
                                     unsigned char key[AUTH_KEY_BYTES]) {
    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char verifier[AUTH_VERIFIER_BYTES];
    const SecretBuf secrets[] = {
        {salt,     sizeof salt},
        {verifier, sizeof verifier},
    };
    if (!lock_secrets(secrets, ARRAY_LEN(secrets))) return AUTH_ERR_CRYPTO;

    randombytes_buf(salt, sizeof salt);

    AuthStatus status = AUTH_ERR_CRYPTO;
    if (derive_keys(password, salt, verifier, key) == 0 &&
        sodium_bin2base64(cfg->salt, sizeof cfg->salt, salt, sizeof salt, AUTH_B64_VARIANT) != nullptr &&
        sodium_bin2base64(cfg->verifier, sizeof cfg->verifier, verifier, sizeof verifier, AUTH_B64_VARIANT) != nullptr) {
        memcpy(cfg->kdf, AUTH_KDF_NAME, sizeof AUTH_KDF_NAME);
        status = AUTH_OK;
    }

    unlock_secrets(secrets, ARRAY_LEN(secrets));
    return status;
}

/* ---------- public API ---------- */

AuthStatus auth_setup_master_password(SfmConfig *cfg, unsigned char key_out[AUTH_KEY_BYTES]) {
    if (cfg == nullptr || key_out == nullptr || cfg->config_path[0] == '\0') {
        return AUTH_ERR_ARGS;
    }
    if (sodium_init() < 0) return AUTH_ERR_CRYPTO;

    char password[AUTH_PASSWORD_MAX];
    char confirm[AUTH_PASSWORD_MAX];
    unsigned char key[AUTH_KEY_BYTES];
    const SecretBuf secrets[] = {
        {password, sizeof password},
        {confirm,  sizeof confirm},
        {key,      sizeof key},
    };
    if (!lock_secrets(secrets, ARRAY_LEN(secrets))) return AUTH_ERR_CRYPTO;

    AuthStatus status = read_password("Choose a master password: ", password, sizeof password);
    if (status == AUTH_OK) {
        if (password[0] == '\0')                 status = AUTH_ERR_EMPTY;
        else if (!is_password_complex(password)) status = AUTH_ERR_WEAK;
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
        if (status == AUTH_OK && save_config(updated.config_path, &updated) != CONFIG_OK) {
            status = AUTH_ERR_SAVE;
        }
        if (status == AUTH_OK) {
            *cfg = updated;
            memcpy(key_out, key, sizeof key);
        }
    }

    unlock_secrets(secrets, ARRAY_LEN(secrets));
    return status;
}

AuthStatus auth_login(const SfmConfig *cfg, unsigned char *key_out) {
    if (cfg == nullptr || key_out == nullptr) return AUTH_ERR_ARGS;
    if (sodium_init() < 0) return AUTH_ERR_CRYPTO;
    if (config_is_first_run(cfg) || strcmp(cfg->kdf, AUTH_KDF_NAME) != 0) {
        return AUTH_ERR_CONFIG;
    }

    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char stored[AUTH_VERIFIER_BYTES];
    const SecretBuf config_secrets[] = {
        {salt,   sizeof salt},
        {stored, sizeof stored},
    };
    if (!lock_secrets(config_secrets, ARRAY_LEN(config_secrets))) return AUTH_ERR_CRYPTO;

    if (!decode_b64(cfg->salt, salt, sizeof salt) ||
        !decode_b64(cfg->verifier, stored, sizeof stored)) {
        unlock_secrets(config_secrets, ARRAY_LEN(config_secrets));
        return AUTH_ERR_CONFIG;
    }

    AuthStatus status = AUTH_ERR_WRONG_PASSWORD;
    unsigned int backoff_sec = 1U;

    while (true) {
        char password[AUTH_PASSWORD_MAX];
        unsigned char verifier[AUTH_VERIFIER_BYTES];
        unsigned char key[AUTH_KEY_BYTES];
        const SecretBuf derived_secrets[] = {
            {verifier, sizeof verifier},
            {key,      sizeof key},
        };

        if (!lock_secret(password, sizeof password)) {
            status = AUTH_ERR_CRYPTO;
            break;
        }
        if (!lock_secrets(derived_secrets, ARRAY_LEN(derived_secrets))) {
            wipe_and_unlock(password, sizeof password);
            status = AUTH_ERR_CRYPTO;
            break;
        }

        status = read_password("Master password: ", password, sizeof password);
        if (status != AUTH_OK) {
            wipe_and_unlock(password, sizeof password);
            unlock_secrets(derived_secrets, ARRAY_LEN(derived_secrets));
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

        unlock_secrets(derived_secrets, ARRAY_LEN(derived_secrets));

        if (status != AUTH_ERR_WRONG_PASSWORD) break;

        // Every failed attempt is audited individually (brute-force trail).
        log_audit_event(cfg, LOG_EVENT_LOGIN, LOG_OUTCOME_FAILURE, nullptr);
        (void)fprintf(stderr, "Wrong password. Waiting %u second%s before next attempt...\n",
                      backoff_sec, (backoff_sec == 1U) ? "" : "s");
        (void)sleep(backoff_sec);
        backoff_sec = (backoff_sec <= (AUTH_BACKOFF_MAX_SEC / 2U)) ? (backoff_sec * 2U) : AUTH_BACKOFF_MAX_SEC;
    }

    unlock_secrets(config_secrets, ARRAY_LEN(config_secrets));
    return status;
}

const char *auth_strerror(AuthStatus status) {
    switch (status) {
        case AUTH_OK:                 return "Success";
        case AUTH_ERR_ARGS:           return "Invalid arguments (internal error)";
        case AUTH_ERR_IO:             return "Cannot read the password (is stdin a terminal?)";
        case AUTH_ERR_TOO_LONG:       return "Password too long (max 64 characters)";
        case AUTH_ERR_EMPTY:          return "Password cannot be empty";
        case AUTH_ERR_WEAK:           return "Password must be 8-64 characters long and include an uppercase letter, lowercase letter, number, and special character";
        case AUTH_ERR_MISMATCH:       return "Passwords do not match";
        case AUTH_ERR_CRYPTO:         return "Cryptographic error";
        case AUTH_ERR_CONFIG:         return "Configuration is missing or corrupt";
        case AUTH_ERR_SAVE:           return "Could not save the configuration";
        case AUTH_ERR_WRONG_PASSWORD: return "Wrong password";
    }
    return "Unknown error";
}
