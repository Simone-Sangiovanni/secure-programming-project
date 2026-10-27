#ifndef SFM_CIPHER_H
#define SFM_CIPHER_H

#include <stddef.h>

/**
 * @file cipher.h
 * @brief Authenticated encryption of memory buffers (libsodium).
 *
 * Algorithm: libsodium "secretstream" (XChaCha20-Poly1305). It encrypts AND
 * authenticates, so a wrong key or any modification of the data is detected
 * on decryption instead of producing garbage.
 *
 * Encrypted layout:
 *
 *   | "SFM1" (4) | version (1) | stream header (24) | ciphertext + tag (n + 17) |
 *
 * The first 5 bytes are authenticated too, so they cannot be altered.
 * A fresh random nonce is part of the stream header, so encrypting the same
 * file twice gives different output.
 *
 * This module works on buffers only and never touches files.
 */

/** Size in bytes of the encryption key (same as AUTH_KEY_BYTES). */
#define CIPHER_KEY_BYTES 32

/** Result codes returned by the cipher functions. */
typedef enum {
    CIPHER_OK = 0,        /**< Success. */
    CIPHER_ERR_ARGS,      /**< NULL pointer passed by the caller (a bug). */
    CIPHER_ERR_INIT,      /**< libsodium could not be initialised. */
    CIPHER_ERR_ALLOC,     /**< Out of memory. */
    CIPHER_ERR_TOO_BIG,   /**< Input so large the output size would overflow. */
    CIPHER_ERR_ENCRYPT,   /**< Encryption failed. */
    CIPHER_ERR_FORMAT,    /**< Not an sfm-encrypted file (bad magic / too short). */
    CIPHER_ERR_VERSION,   /**< Encrypted by an unsupported version. */
    CIPHER_ERR_AUTH       /**< Wrong key, or the data was modified/corrupted/truncated. */
} CipherStatus;

/**
 * @brief Encrypts a buffer.
 *
 * @param key     CIPHER_KEY_BYTES-byte key.
 * @param in      Plaintext (may be NULL only if @p in_len is 0).
 * @param in_len  Plaintext length.
 * @param out     Receives a new buffer with the encrypted data. Release it
 *                with cipher_free().
 * @param out_len Receives the length of @p out.
 * @return CIPHER_OK or the reason it failed (nothing is allocated on failure).
 */
[[nodiscard]] CipherStatus cipher_encrypt(const unsigned char key[CIPHER_KEY_BYTES],
                                          const unsigned char *in, size_t in_len,
                                          unsigned char **out, size_t *out_len);

/**
 * @brief Decrypts a buffer produced by cipher_encrypt().
 *
 * Nothing is returned unless the authentication tag verifies, so a caller
 * never receives data from a wrong key or a tampered file.
 *
 * @param key     CIPHER_KEY_BYTES-byte key.
 * @param in      Encrypted data.
 * @param in_len  Length of @p in.
 * @param out     Receives a new buffer with the plaintext. Release it with
 *                cipher_free().
 * @param out_len Receives the plaintext length.
 * @return CIPHER_OK, CIPHER_ERR_FORMAT / _VERSION if it is not a valid sfm
 *         file, CIPHER_ERR_AUTH for a wrong key or modified data, or another
 *         error code.
 */
[[nodiscard]] CipherStatus cipher_decrypt(const unsigned char key[CIPHER_KEY_BYTES],
                                          const unsigned char *in, size_t in_len,
                                          unsigned char **out, size_t *out_len);

/**
 * @brief Wipes a buffer with zeros and frees it. Safe to call with NULL.
 *
 * Use it for every buffer that held plaintext.
 */
void cipher_free(unsigned char *buf, size_t len);

/** Returns a human-readable message for a CipherStatus (never NULL). */
[[nodiscard]] const char *cipher_strerror(CipherStatus status);

#endif