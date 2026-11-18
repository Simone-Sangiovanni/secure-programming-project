#include "auth.h"
#include <assert.h>
#include <ctype.h>
#include <sodium.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define AUTH_SALT_BYTES crypto_pwhash_SALTBYTES         // 16-byte length for cryptographic salt
#define AUTH_VERIFIER_BYTES 32                        // byte length for verifier
#define AUTH_B64_VARIANT sodium_base64_VARIANT_ORIGINAL // standard Base64 format
#define AUTH_KDF_NAME "argon2id"
#define AUTH_BACKOFF_MAX_SEC 30U

/*
 * Domain separation contexts for libsodium's key derivation functions (crypto_kdf).
 * Libsodium requires context strings to be exactly 8 characters long. They ensure that
 * even if keys are derived from the same master secret, a key used for verification (sfmverif)
 * cannot be misused as a key used for wrapping per-file DEKs (sfmkek!!).
 */
#define CTX_VERIFIER "sfmverif"
#define CTX_KEK      "sfmkek!!"

/*
 * Argon2id cost parameters. These define how much CPU power (ops_limit) and RAM (mem_limit)
 * Argon2id is allowed to consume when hashing a password.
 */
#define AUTH_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define AUTH_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

// Compile-time checks ensuring config struct fields are large enough for Base64 strings.
static_assert(sodium_base64_ENCODED_LEN(AUTH_SALT_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->salt), "config.salt too small for a Base64 salt");
static_assert(sodium_base64_ENCODED_LEN(AUTH_VERIFIER_BYTES, AUTH_B64_VARIANT) <=
              sizeof(((SfmConfig *)nullptr)->verifier), "config.verifier too small for Base64 verifier");
static_assert(sizeof(((SfmConfig *)nullptr)->kdf) >= sizeof(AUTH_KDF_NAME), "config.kdf too small");
static_assert(AUTH_KEY_BYTES == crypto_kdf_KEYBYTES, "key size mismatch");



/* ---------------------------------------------------- */
/* ---------- helpers (private to this file) ---------- */
/* ---------------------------------------------------- */



/**
 * @brief Initialises libsodium. Safe to call many times.
 * @return true on success, false if libsodium could not be initialised.
 */
static bool init_sodium(void) {
    return sodium_init() >= 0;  // 0 = initialised now, 1 = already initialised
}

/**
 * @brief Zeroes and unlocks a locked memory buffer.
 */
static void wipe_and_unlock(void *buf, size_t size) {
    sodium_memzero(buf, size);
    (void)sodium_munlock(buf, size);
}

/**
 * @brief Reads one line from the terminal without echoing it.
 *
 * Disables ECHO on stdin, prints @p prompt on stderr, reads a line, strips
 * the trailing newline and always restores the terminal settings. Fails if
 * stdin is not a terminal or if the line does not fit in @p buf.
 *
 * @param prompt Text shown to the user.
 * @param buff   Output buffer.
 * @param size   Size of @p buff in bytes.
 * @return AUTH_OK, AUTH_ERR_IO or AUTH_ERR_TOO_LONG.
 */
static AuthStatus read_password(const char *prompt, char *buff, size_t size) {
    struct termios old_settings;
    // Fetch current terminal configuration attributes on STDIN_FILENO
    if (tcgetattr(STDIN_FILENO, &old_settings) != 0) return AUTH_ERR_IO;

    // Copy settings and clear the ECHO flag so typed characters are hidden
    struct termios no_echo = old_settings;
    no_echo.c_lflag &= ~(tcflag_t)ECHO;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo) != 0) return AUTH_ERR_IO;

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
            // No newline found: input exceeded buffer; discard remainder
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { /* discard */ }
            status = AUTH_ERR_TOO_LONG;
        }
    }

    // Always restore the terminal, even after an error.
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings) != 0 && status == AUTH_OK) {
        status = AUTH_ERR_IO;
    }

    (void)fputc('\n', stderr);  // the user's Enter was not echoed
    if (status != AUTH_OK) sodium_memzero(buff, size);
    return status;
}

/**
 * @brief Derives the verifier and the file-encryption key from a password.
 */
static int derive_keys(const char *password, const unsigned char salt[AUTH_SALT_BYTES],
                       unsigned char verifier_out[AUTH_VERIFIER_BYTES],
                       unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char master[crypto_kdf_KEYBYTES];
    if (sodium_mlock(master, sizeof master) != 0) {
        return -1;
    }

    int rc = crypto_pwhash(master, sizeof master, password, strlen(password),
                           salt, AUTH_OPSLIMIT, AUTH_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);

    if (rc == 0) {
        rc = crypto_kdf_derive_from_key(verifier_out, AUTH_VERIFIER_BYTES, 1,
                                        CTX_VERIFIER, master);
    }
    if (rc == 0) {
        rc = crypto_kdf_derive_from_key(key_out, AUTH_KEY_BYTES, 2,
                                        CTX_KEK, master);
    }

    wipe_and_unlock(master, sizeof master);
    return rc == 0 ? 0 : -1;
}

/**
 * @brief Decodes a Base64 string into exactly @p expected bytes.
 */
static bool decode_b64(const char *b64, unsigned char *out, size_t expected) {
    size_t decoded = 0;
    if (sodium_base642bin(out, expected, b64, strlen(b64), nullptr, &decoded,
                          nullptr, AUTH_B64_VARIANT) != 0) {
        return false;
    }
    return decoded == expected;
}

/**
 * @brief Generates a new salt, derives the keys and writes salt, verifier
 *        and kdf name (Base64) into @p cfg.
 */
static AuthStatus create_credentials(const char *password, SfmConfig *cfg,
                                     unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char verifier[AUTH_VERIFIER_BYTES];
    unsigned char key[AUTH_KEY_BYTES];

    if (sodium_mlock(salt, sizeof salt) != 0) {
        return AUTH_ERR_CRYPTO;
    }
    if (sodium_mlock(verifier, sizeof verifier) != 0) {
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CRYPTO;
    }
    if (sodium_mlock(key, sizeof key) != 0) {
        wipe_and_unlock(verifier, sizeof verifier);
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CRYPTO;
    }

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

/**
 * @brief Checks if a password meets the complexity requirements.
 *
 * Requirements:
 * - Length between 8 and 64 bytes.
 * - At least one uppercase letter, lowercase letter, digit, and special character.
 */
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



/* -------------------------------- */
/* ---------- public API ---------- */
/* -------------------------------- */



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
    if (sodium_mlock(confirm, sizeof confirm) != 0) {
        wipe_and_unlock(password, sizeof password);
        return AUTH_ERR_CRYPTO;
    }
    if (sodium_mlock(key, sizeof key) != 0) {
        wipe_and_unlock(confirm, sizeof confirm);
        wipe_and_unlock(password, sizeof password);
        return AUTH_ERR_CRYPTO;
    }

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

    // Verify that the configured KDF matches what this build supports
    if (strcmp(cfg->kdf, AUTH_KDF_NAME) != 0) {
        return AUTH_ERR_CONFIG;
    }

    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char stored[AUTH_VERIFIER_BYTES];

    if (sodium_mlock(salt, sizeof salt) != 0) {
        return AUTH_ERR_CRYPTO;
    }
    if (sodium_mlock(stored, sizeof stored) != 0) {
        wipe_and_unlock(salt, sizeof salt);
        return AUTH_ERR_CRYPTO;
    }

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
        if (sodium_mlock(verifier, sizeof verifier) != 0) {
            wipe_and_unlock(password, sizeof password);
            status = AUTH_ERR_CRYPTO;
            break;
        }
        if (sodium_mlock(key, sizeof key) != 0) {
            wipe_and_unlock(verifier, sizeof verifier);
            wipe_and_unlock(password, sizeof password);
            status = AUTH_ERR_CRYPTO;
            break;
        }

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
