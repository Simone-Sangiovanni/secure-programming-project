#include "auth.h"

#include <ctype.h>
#include <errno.h>
#include <sodium.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "../cli/cli.h"
#include "../log/log.h"

#define AUTH_SALT_BYTES      crypto_pwhash_SALTBYTES
#define AUTH_MASTER_BYTES    32
#define AUTH_VERIFIER_BYTES  32
#define AUTH_B64_VARIANT     sodium_base64_VARIANT_ORIGINAL
#define AUTH_KDF_NAME        "argon2id"
#define AUTH_BACKOFF_MAX_SEC 30U
#define HKDF_INFO_VERIFIER   "sfm-verifier-v1"
#define HKDF_INFO_KEK        "sfm-kek-v1"

static_assert(sodium_base64_ENCODED_LEN(AUTH_SALT_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->salt), "config.salt buffer too small");
static_assert(sodium_base64_ENCODED_LEN(AUTH_VERIFIER_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->verifier), "config.verifier buffer too small");
static_assert(sizeof(((SfmConfig *)nullptr)->kdf) >= sizeof(AUTH_KDF_NAME), "config.kdf buffer too small");
static_assert(AUTH_VERIFIER_BYTES == crypto_auth_hmacsha256_BYTES, "verifier size mismatch");
static_assert(AUTH_KEY_BYTES == crypto_auth_hmacsha256_BYTES, "KEK size mismatch");

typedef struct {
    void *ptr;
    size_t size;
} SecretSpan;

static bool lock_secret(void *buf, size_t size) {
    if (sodium_mlock(buf, size) != 0) return false;
    cli_register_secret(buf, size);
    return true;
}

static void wipe_secret(void *buf, size_t size) {
    cli_unregister_secret(buf);
    sodium_memzero(buf, size);
    (void)sodium_munlock(buf, size);
}

static void wipe_secrets(const SecretSpan *spans, size_t count) {
    for (size_t i = count; i > 0; i--) {
        wipe_secret(spans[i - 1].ptr, spans[i - 1].size);
    }
}

static bool lock_secrets(const SecretSpan *spans, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (!lock_secret(spans[i].ptr, spans[i].size)) {
            wipe_secrets(spans, i);
            return false;
        }
    }
    return true;
}

/* Reads a line from stdin with ECHO disabled directly into a locked buffer. */
static AuthStatus read_password(const char *prompt, char *buf, size_t size) {
    struct termios saved;
    if (tcgetattr(STDIN_FILENO, &saved) != 0) return AUTH_ERR_IO;

    struct termios no_echo = saved;
    no_echo.c_lflag &= ~(tcflag_t)ECHO;

    cli_register_termios(&saved);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo) != 0) {
        cli_unregister_termios();
        return AUTH_ERR_IO;
    }

    (void)fputs(prompt, stderr);
    (void)fflush(stderr);

    AuthStatus status = AUTH_OK;
    size_t len = 0;
    bool too_long = false;

    while (true) {
        char ch;
        const ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            status = AUTH_ERR_IO;
            break;
        }
        if (ch == '\n') break;
        if (len + 2 < size) buf[len++] = ch;
        else too_long = true;
    }

    buf[len] = '\0';
    if (status == AUTH_OK && too_long) status = AUTH_ERR_TOO_LONG;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved) != 0 && status == AUTH_OK) status = AUTH_ERR_IO;
    cli_unregister_termios();

    (void)fputc('\n', stderr);
    if (status != AUTH_OK) sodium_memzero(buf, size);
    return status;
}

static bool is_password_complex(const char *pw) {
    const size_t len = strlen(pw);
    if (len < 8 || len > 64) return false;

    bool upper = false, lower = false, digit = false, special = false;
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)pw[i];
        if (isupper(c))      upper = true;
        else if (islower(c)) lower = true;
        else if (isdigit(c)) digit = true;
        else                 special = true;
    }
    return upper && lower && digit && special;
}

/* RFC 5869 single-block HKDF-SHA256 (Extract + Expand). */
static bool hkdf_sha256(unsigned char out[crypto_auth_hmacsha256_BYTES],
                        const unsigned char *ikm, size_t ikm_len,
                        const unsigned char *salt, size_t salt_len,
                        const char *info) {
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    if (!lock_secret(prk, sizeof prk)) return false;

    const unsigned char counter = 0x01U;
    crypto_auth_hmacsha256_state hmac;
    const bool ok =
        crypto_auth_hmacsha256_init(&hmac, salt, salt_len) == 0 &&
        crypto_auth_hmacsha256_update(&hmac, ikm, ikm_len) == 0 &&
        crypto_auth_hmacsha256_final(&hmac, prk) == 0 &&
        crypto_auth_hmacsha256_init(&hmac, prk, sizeof prk) == 0 &&
        crypto_auth_hmacsha256_update(&hmac, (const unsigned char *)info, strlen(info)) == 0 &&
        crypto_auth_hmacsha256_update(&hmac, &counter, 1U) == 0 &&
        crypto_auth_hmacsha256_final(&hmac, out) == 0;

    sodium_memzero(&hmac, sizeof hmac);
    wipe_secret(prk, sizeof prk);
    return ok;
}

static bool derive_keys(const char *password, const unsigned char salt[AUTH_SALT_BYTES],
                        unsigned char verifier_out[AUTH_VERIFIER_BYTES],
                        unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char master[AUTH_MASTER_BYTES];
    if (!lock_secret(master, sizeof master)) return false;

    const bool ok =
        crypto_pwhash(master, sizeof master, password, strlen(password), salt,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) == 0 &&
        hkdf_sha256(verifier_out, master, sizeof master, salt, AUTH_SALT_BYTES, HKDF_INFO_VERIFIER) &&
        hkdf_sha256(key_out, master, sizeof master, salt, AUTH_SALT_BYTES, HKDF_INFO_KEK);

    wipe_secret(master, sizeof master);
    return ok;
}

static bool decode_b64(const char *b64, unsigned char *out, size_t expected) {
    size_t decoded = 0;
    return sodium_base642bin(out, expected, b64, strlen(b64), nullptr, &decoded,
                             nullptr, AUTH_B64_VARIANT) == 0 && decoded == expected;
}

static AuthStatus create_credentials(const char *password, SfmConfig *cfg,
                                     unsigned char key[AUTH_KEY_BYTES]) {
    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char verifier[AUTH_VERIFIER_BYTES];
    const SecretSpan spans[] = {{salt, sizeof salt}, {verifier, sizeof verifier}};
    if (!lock_secrets(spans, 2)) return AUTH_ERR_CRYPTO;

    randombytes_buf(salt, sizeof salt);

    AuthStatus status = AUTH_ERR_CRYPTO;
    if (derive_keys(password, salt, verifier, key) &&
        sodium_bin2base64(cfg->salt, sizeof cfg->salt, salt, sizeof salt, AUTH_B64_VARIANT) != nullptr &&
        sodium_bin2base64(cfg->verifier, sizeof cfg->verifier, verifier, sizeof verifier, AUTH_B64_VARIANT) != nullptr) {
        memcpy(cfg->kdf, AUTH_KDF_NAME, sizeof AUTH_KDF_NAME);
        status = AUTH_OK;
    }

    wipe_secrets(spans, 2);
    return status;
}

AuthStatus auth_setup_master_password(SfmConfig *cfg, unsigned char key_out[AUTH_KEY_BYTES]) {
    if (cfg == nullptr || key_out == nullptr || cfg->config_path[0] == '\0') return AUTH_ERR_ARGS;
    if (sodium_init() < 0) return AUTH_ERR_CRYPTO;

    char password[AUTH_PASSWORD_MAX];
    char confirm[AUTH_PASSWORD_MAX];
    unsigned char key[AUTH_KEY_BYTES];
    const SecretSpan spans[] = {
        {password, sizeof password},
        {confirm,  sizeof confirm},
        {key,      sizeof key},
    };
    if (!lock_secrets(spans, 3)) return AUTH_ERR_CRYPTO;

    AuthStatus status = read_password("Choose a master password: ", password, sizeof password);
    if (status == AUTH_OK) {
        if (password[0] == '\0')                 status = AUTH_ERR_EMPTY;
        else if (!is_password_complex(password)) status = AUTH_ERR_WEAK;
    }

    if (status == AUTH_OK) {
        status = read_password("Confirm master password: ", confirm, sizeof confirm);
        if (status == AUTH_OK && strcmp(password, confirm) != 0) status = AUTH_ERR_MISMATCH;
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

    wipe_secrets(spans, 3);
    return status;
}

AuthStatus auth_login(const SfmConfig *cfg, unsigned char *key_out) {
    if (cfg == nullptr || key_out == nullptr) return AUTH_ERR_ARGS;
    if (sodium_init() < 0) return AUTH_ERR_CRYPTO;
    if (config_is_first_run(cfg) || strcmp(cfg->kdf, AUTH_KDF_NAME) != 0) return AUTH_ERR_CONFIG;

    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char stored[AUTH_VERIFIER_BYTES];
    char password[AUTH_PASSWORD_MAX];
    unsigned char verifier[AUTH_VERIFIER_BYTES];
    unsigned char key[AUTH_KEY_BYTES];
    const SecretSpan spans[] = {
        {salt,     sizeof salt},
        {stored,   sizeof stored},
        {password, sizeof password},
        {verifier, sizeof verifier},
        {key,      sizeof key},
    };
    if (!lock_secrets(spans, 5)) return AUTH_ERR_CRYPTO;

    if (!decode_b64(cfg->salt, salt, sizeof salt) ||
        !decode_b64(cfg->verifier, stored, sizeof stored)) {
        wipe_secrets(spans, 5);
        return AUTH_ERR_CONFIG;
    }

    AuthStatus status = AUTH_ERR_WRONG_PASSWORD;
    unsigned int backoff_sec = 1U;

    while (true) {
        status = read_password("Master password: ", password, sizeof password);
        if (status != AUTH_OK) break;

        const bool derived = derive_keys(password, salt, verifier, key);
        sodium_memzero(password, sizeof password);

        if (!derived) {
            status = AUTH_ERR_CRYPTO;
            break;
        }
        if (sodium_memcmp(verifier, stored, sizeof stored) == 0) {
            memcpy(key_out, key, sizeof key);
            status = AUTH_OK;
            break;
        }

        sodium_memzero(verifier, sizeof verifier);
        sodium_memzero(key, sizeof key);

        // Log every failed attempt individually for brute-force auditing.
        log_audit_event(cfg, LOG_EVENT_LOGIN, LOG_OUTCOME_FAILURE, nullptr);
        (void)fprintf(stderr, "Wrong password. Waiting %u second%s before next attempt...\n",
                      backoff_sec, (backoff_sec == 1U) ? "" : "s");
        (void)sleep(backoff_sec);
        backoff_sec = (backoff_sec <= AUTH_BACKOFF_MAX_SEC / 2U) ? (backoff_sec * 2U) : AUTH_BACKOFF_MAX_SEC;
    }

    wipe_secrets(spans, 5);
    return status;
}

const char *auth_strerror(AuthStatus status) {
    static const char *const messages[] = {
        [AUTH_OK]                 = "Success",
        [AUTH_ERR_ARGS]           = "Invalid arguments (internal error)",
        [AUTH_ERR_IO]             = "Cannot read the password (is stdin a terminal?)",
        [AUTH_ERR_TOO_LONG]       = "Password too long (max 64 characters)",
        [AUTH_ERR_EMPTY]          = "Password cannot be empty",
        [AUTH_ERR_WEAK]           = "Password must be 8-64 characters long and include an uppercase letter, lowercase letter, number, and special character",
        [AUTH_ERR_MISMATCH]       = "Passwords do not match",
        [AUTH_ERR_CRYPTO]         = "Cryptographic error",
        [AUTH_ERR_CONFIG]         = "Configuration is missing or corrupt",
        [AUTH_ERR_SAVE]           = "Could not save the configuration",
        [AUTH_ERR_WRONG_PASSWORD] = "Wrong password",
    };
    const size_t idx = (size_t)status;
    return (idx < sizeof messages / sizeof messages[0] && messages[idx] != nullptr)
           ? messages[idx] : "Unknown error";
}