// enable POSIX standard features necessary when dealing with therminal controls (termios.h, unistd.h)
#include <sodium/core.h>
#include <sodium/crypto_kdf.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/randombytes.h>
#include <stddef.h>
#define _POSIX_C_SOURCE 200809L

// standard POSIX headers for low level terminal I/O handling (hide password input in the terminal)
#include <termios.h>
#include <unistd.h>

// used for password hashing and key derivation
#include <sodium.h>
#include <sodium/utils.h>
  
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "auth.h"


#define AUTH_SALT_BYTES crypto_pwhash_SALTBYTES // 16 - byte length for cryptographic salt
#define AUTH_VERIFIER_BYTES 32 // byte length for verifier
#define AUTH_B64_VARIANT sodium_base64_VARIANT_ORIGINAL // standard Base64 format
#define AUTH_KDF_NAME "argon2id"

/*
  domain separation contexts for libsodium's key derivation functions (crypto_kdf).
  Libsodium requires context strings to be exactly 8 characters long. They ensure that 
  even if keys are derived from the same master secret, a key used for verification (sfmverif) 
  cannot be misused as a key used for file encryption (sfmfkey!).
*/
#define CTX_VERIFIER "sfmverif"
#define CTX_FILE_KEY "sfmfkey!"

/*
  Argon2id cost parameters. These define how much CPU power (ops_limit) and RAM (mem_limit) 
  Argon2id is allowed to consume when hashing a password.
  
  TODO(security): store these in the config so they can be raised later without breaking 
  existing vaults.
*/
#define AUTH_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define AUTH_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE

// The Base64 text must fit in the config fields, otherwise libsodium aborts.
/*
  A compile-time check that evaluates an expression before the program is even built. 
  If the condition fails, the compiler stops and throws an error.

  This guarantees that the configuration struct has enough allocated space to hold the Base64-encoded salt. 
  If the struct field is too small, libsodium would crash or overflow at runtime, so catching this at 
  compile time prevents bugs
*/
static_assert(sodium_base64_ENCODED_LEN(AUTH_SALT_BYTES, AUTH_B64_VARIANT) <= 
    sizeof(((SfmConfig *)nullptr)->salt), "sonfig.salt too small for a Base64 salt");
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
    return sodium_init() >= 0; // 0 = initialised now, 1 = already initialised
}

/**
* @brief Reads one line from the terminal without echoing it.
*
* Disables ECHO on stdin, prints @p prompt on stderr, reads a line, strips
* the trailing newline and always restores the terminal settings. Fails if
* stdin is not a terminal (e.g. input piped from a file) or if the line does
* not fit in @p buf; in that case the rest of the line is discarded and
* @p buf is wiped.
*
* @param prompt Text shown to the user.
* @param buf    Output buffer.
* @param size   Size of @p buf in bytes.
* @return AUTH_OK, AUTH_ERR_IO or AUTH_ERR_TOO_LONG.
*/

static AuthStatus read_password(const char *prompt, char *buff, size_t size) {
    struct termios old_settings;
    // fetch the current terminal configuration attributes to restore them later
    if (tcgetattr(STDERR_FILENO, &old_settings) != 0) return AUTH_ERR_IO;

    // copies the settings and clears the ECHO flag (does not print the characters in the terminal)
    struct termios no_echo = old_settings;
    no_echo.c_lflag &= ~(tcflag_t)ECHO;
    // apply immediately the new settings to the terminal
    if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo) != 0) return AUTH_ERR_IO;

    // use stderr instead of stdout because it is unbuffered: the output goes directly to the terminal instead of
    // being stored in a buffer, making the output visible even if the stdout is being captured elsewhere
    (void)fputs(prompt, stderr);
    // guarantee instant rendering
    (void)fflush(stderr);

    AuthStatus status = AUTH_OK;
    // reads a maximum number of characters (defined by 'size') from stdin to the buffer
    if(fgets(buff, (int)size, stdin) == nullptr) {
        status = AUTH_ERR_IO;
    } else {
        // find the '\n' char and substitute it with '\0' to close the string
        const size_t len = strcspn(buff, "\n");
        if (buff[len] == '\n') {
            buff[len] = '\0';
        } else {
            // no newline found: the input was longer than the buffer - avoid buffer overflow
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { /* discard */} // clears the input buffer
            status = AUTH_ERR_TOO_LONG;
        }
    }

    // Always restore the terminal, even after an error.
    if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings) != 0 && status == AUTH_OK) {
        status = AUTH_ERR_IO;
    }
    (void)fputc('\n', stderr); // the user's Enter was not echoed

    if(status != AUTH_OK) sodium_memzero(buff, size);
    return status;
}

/**
* @brief Derives the verifier and the file-encryption key from a password.
*
* Runs Argon2id(password, salt) to get a master key, then derives two
* independent subkeys from it with different KDF contexts. The master key
* is wiped before returning. This call is deliberately slow and uses a lot
* of memory (that is what makes brute-forcing the password expensive).
*
* @param password     NUL-terminated password.
* @param salt         AUTH_SALT_BYTES bytes of salt.
* @param verifier_out Receives AUTH_VERIFIER_BYTES bytes.
* @param key_out      Receives AUTH_KEY_BYTES bytes.
* @return 0 on success, -1 on failure (e.g. out of memory).
*/
static int derive_keys(const char *password, const unsigned char salt[AUTH_SALT_BYTES], 
        unsigned char verifier_out[AUTH_VERIFIER_BYTES], 
        unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char master[crypto_kdf_KEYBYTES];

    // generate the master key with argon21d
    int rc = crypto_pwhash(master, sizeof master, password, strlen(password), 
        salt, AUTH_OPSLIMIT, AUTH_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);

    // derive the subkeys: verifier and file encryption key
    if(rc == 0) {
        rc = crypto_kdf_derive_from_key(verifier_out, AUTH_VERIFIER_BYTES, 1,
            CTX_VERIFIER, master);
    }
    if (rc == 0) {
        rc = crypto_kdf_derive_from_key(key_out, AUTH_KEY_BYTES, 2, 
            CTX_FILE_KEY, master);
    }

    sodium_memzero(master, sizeof master);
    return rc == 0 ? 0 : -1;
}

/**
 * @brief Decodes a Base64 string into exactly @p expected bytes.
 *
 * @param b64      NUL-terminated Base64 text.
 * @param out      Output buffer of at least @p expected bytes.
 * @param expected Exact number of bytes the text must decode to.
 * @return true on success; false if the text is invalid or has another length.
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
*
* @param password NUL-terminated password.
* @param cfg      Config to fill (a working copy; the caller commits it).
* @param key_out  Receives the AUTH_KEY_BYTES-byte file-encryption key.
* @return AUTH_OK or AUTH_ERR_CRYPTO.
*/
static AuthStatus create_credentials(const char *password, SfmConfig *cfg, unsigned char key_out[AUTH_KEY_BYTES]) {
    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char verifier[AUTH_VERIFIER_BYTES];
    unsigned char key[AUTH_KEY_BYTES];
    AuthStatus status = AUTH_ERR_CRYPTO;

    // generate the salt
    randombytes_buf(salt, sizeof salt);

    // derive the keys, encode them in base64 and store them in the config
    if(derive_keys(password, salt, verifier, key) == 0 && 
            sodium_bin2base64(cfg->salt, sizeof cfg->salt, salt, sizeof salt, AUTH_B64_VARIANT) != nullptr &&
            sodium_bin2base64(cfg->verifier, sizeof cfg->verifier, verifier, sizeof verifier, AUTH_B64_VARIANT) != nullptr) {
        memcpy(cfg->kdf, AUTH_KDF_NAME, sizeof AUTH_KDF_NAME); // include the '\0'
        memcpy(key_out, key, sizeof key);
        status = AUTH_OK;
    }

    sodium_memzero(salt, sizeof salt); // (the salt is not secret, but no reason to keep it)
    sodium_memzero(verifier, sizeof(verifier));
    sodium_memzero(key, sizeof(key));

    return status;
}


/* -------------------------------- */
/* ---------- public API ---------- */
/* -------------------------------- */


/**
 * @brief Implementation of auth_setup_master_password().
 *
 * Flow: prompt -> confirm -> compare -> create credentials in a working
 * copy of the config -> save that copy to disk -> commit it to @p cfg.
 * Password buffers and keys are wiped on every path.
 */
AuthStatus auth_setup_master_password(SfmConfig *cfg, unsigned char *key_out) {
    // Validate input parameters. Ensure pointers aren't null and the file path isn't empty.
    if (cfg == nullptr || key_out == nullptr || cfg->config_path[0] == '\0') {
        return AUTH_ERR_ARGS;
    }
    // Initialize the libsodium cryptographic library; return a crypto error if initialization fails
    if (!init_sodium()) return AUTH_ERR_CRYPTO;

    char password[AUTH_PASSWORD_MAX];
    char confirm[AUTH_PASSWORD_MAX];
    unsigned char key[AUTH_KEY_BYTES];

    AuthStatus status = read_password("Choose a master password: ", password, sizeof password);
    if (status == AUTH_OK) {
        status = read_password("Confirm master password: ", confirm, sizeof confirm);
    }

    // TODO(security): enforce a minimum length / strength policy.
    if (status == AUTH_OK && password[0] == '\0') status = AUTH_ERR_EMPTY;
    if (status == AUTH_OK && strcmp(password, confirm) != 0) status = AUTH_ERR_MISMATCH;

    // create a copy of the configuration to avoid modifying original data prematurely,
    // create credentials and then update the original data in case of success
    if (status == AUTH_OK) {
        printf("Generating keys (this takes a moment)...\n");
        SfmConfig updated = *cfg;

        status = create_credentials(password, &updated, key);

        if (status == AUTH_OK) {
            if (save_config(updated.config_path, &updated) == CONFIG_OK) {
                *cfg = updated; // commit only after the file is safely written
                memcpy(key_out, key, sizeof key);
            } else {
                status = AUTH_ERR_SAVE;
            }
        }
    }

    // wipe sensitive data
    sodium_memzero(password, sizeof password);
    sodium_memzero(confirm, sizeof confirm);
    sodium_memzero(key, sizeof key);
    return status;
}

/**
 * @brief Implementation of auth_login().
 *
 * Decodes the stored salt and verifier once, then for each attempt: read
 * password -> derive verifier with Argon2id -> compare in constant time
 * with sodium_memcmp. The derived values are wiped after every attempt.
 */
AuthStatus auth_login(const SfmConfig *cfg, unsigned char *key_out) {
    // Validate input parameters. Ensure config and output key pointers aren't null
    if (cfg == nullptr || key_out == nullptr) return AUTH_ERR_ARGS;
    // Initialize libsodium; return a crypto error if initialization fails
    if (!init_sodium()) return AUTH_ERR_CRYPTO;
    // Check if the application is in a first-run stat.
    if (config_is_first_run(cfg)) return AUTH_ERR_CONFIG;

    unsigned char salt[AUTH_SALT_BYTES];
    unsigned char stored[AUTH_VERIFIER_BYTES];
    // Decode the base64-encoded salt and verifier from the config struct into raw bytes
    if (!decode_b64(cfg->salt, salt, sizeof salt) ||
            !decode_b64(cfg->verifier, stored, sizeof stored)) {
        return AUTH_ERR_CONFIG;
    }

    AuthStatus status = AUTH_ERR_WRONG_PASSWORD;

    // Loop through allowed login attempts (up to AUTH_MAX_ATTEMPTS)
    for (int attempt = 1; attempt <= AUTH_MAX_ATTEMPTS; attempt++) {
        char password[AUTH_PASSWORD_MAX];
        unsigned char verifier[AUTH_VERIFIER_BYTES];
        unsigned char key[AUTH_KEY_BYTES];

        const AuthStatus rs = read_password("Master password: ", password, sizeof password);

        if (rs != AUTH_OK) {
            status = rs;
            break;
        }

        // Derive the verification hash and key from the entered password using the salt (Argon2id)
        const int rc = derive_keys(password, salt, verifier, key);
        // Immediately wipe the plain-text password from memory right after derivation
        sodium_memzero(password, sizeof password);

        if (rc != 0) {
            status = AUTH_ERR_CRYPTO;
        } 
        // Compare the derived verifier against the stored verifier in constant time to prevent timing attacks.
        else if (sodium_memcmp(verifier, stored, sizeof stored) == 0) {
            memcpy(key_out, key, sizeof key);
            status = AUTH_OK;
        } else {
            (void)fprintf(stderr, "Wrong password (%d/%d).\n", attempt, AUTH_MAX_ATTEMPTS);
        }

        // wipe sensitive data
        sodium_memzero(verifier, sizeof(verifier));
        sodium_memzero(key, sizeof(key));
        if (status != AUTH_ERR_WRONG_PASSWORD) break;
    }

    // wipe sensitive data
    sodium_memzero(salt, sizeof salt);
    sodium_memzero(stored, sizeof stored);
    return status;
}

/**
 * @brief Implementation of auth_strerror().
 */
const char *auth_strerror(AuthStatus status) {
    switch (status) {
        case AUTH_OK: return "Success";
        case AUTH_ERR_ARGS: return "Invalid arguments (internal error)";
        case AUTH_ERR_IO: return "Cannot read the password (is stdin a terminal?)";
        case AUTH_ERR_TOO_LONG: return "Password too long";
        case AUTH_ERR_EMPTY: return "Password cannot be empty";
        case AUTH_ERR_MISMATCH: return "Passwords do not match";
        case AUTH_ERR_CRYPTO: return "Cryptographic error";
        case AUTH_ERR_CONFIG: return "Configuration is missing or corrupt";
        case AUTH_ERR_SAVE: return "Could not save the configuration";
        case AUTH_ERR_WRONG_PASSWORD: return "Wrong password";
    }
    return "Unknown error";
}
