#ifndef SFM_CIPHER_H
#define SFM_CIPHER_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file cipher.h
 * @brief Authenticated, chunk-by-chunk encryption (libsodium secretstream,
 *        XChaCha20-Poly1305).
 *
 * A file is encrypted as a sequence of independent-size chunks so memory use
 * stays constant (about 2 chunks) whatever the file size. Every chunk is
 * authenticated, and the stream as a whole is protected against reordering,
 * duplication, removal and truncation: the last chunk carries a special
 * FINAL mark that a decryptor insists on seeing.
 *
 * Encrypted file layout (format version 2):
 *
 *   | "SFM1" (4) | version=2 (1) | stream header (24) | chunk 1 | chunk 2 | ... | last chunk |
 *
 * where every chunk is  ciphertext (up to 128 KiB) + 17-byte tag.
 * All chunks hold exactly CIPHER_CHUNK_SIZE bytes of plaintext except the
 * last one, which holds between 0 and CIPHER_CHUNK_SIZE (0 only for an
 * empty file). The first 5 bytes are authenticated too.
 *
 * This module only transforms memory buffers; it never touches files.
 */

/**
 * Plaintext bytes per chunk: 128 KiB = 131072.
 *
 * Written as a plain literal on purpose: an expression like (128U * 1024U)
 * is a multiplication done in 32-bit unsigned int, and every place that
 * uses the macro in a 64-bit context (size_t, uint64_t) would trigger
 * clang-tidy's bugprone-implicit-widening-of-multiplication-result.
 * cipher.c has a static_assert that checks the value.
 */
#define CIPHER_CHUNK_SIZE 131072U

/** Authentication tag added to every chunk. */
#define CIPHER_TAG_BYTES 17U

/** Size of the encrypted-file header (magic + version + stream header). */
#define CIPHER_HEADER_BYTES 29U

/** Size in bytes of the encryption key (same as AUTH_KEY_BYTES). */
#define CIPHER_KEY_BYTES 32

/** Result codes returned by the cipher functions. */
typedef enum {
    CIPHER_OK = 0,        /**< Success. */
    CIPHER_ERR_ARGS,      /**< NULL pointer or bad size passed by the caller (a bug). */
    CIPHER_ERR_INIT,      /**< libsodium could not be initialised. */
    CIPHER_ERR_ALLOC,     /**< Out of memory. */
    CIPHER_ERR_TOO_BIG,   /**< Chunk larger than CIPHER_CHUNK_SIZE. */
    CIPHER_ERR_ENCRYPT,   /**< Encryption failed. */
    CIPHER_ERR_FORMAT,    /**< Not an sfm-encrypted file (bad magic / header). */
    CIPHER_ERR_VERSION,   /**< Encrypted by an unsupported format version. */
    CIPHER_ERR_AUTH       /**< Wrong key, or the data was modified/corrupted/truncated. */
} CipherStatus;

/** State of an encryption or decryption in progress (opaque). */
typedef struct CipherStream CipherStream;

/**
 * @brief Starts encrypting a new file.
 *
 * @param key    CIPHER_KEY_BYTES-byte key.
 * @param stream Receives the state. Release it with cipher_stream_free().
 * @param header Receives CIPHER_HEADER_BYTES bytes that must be written at
 *               the very beginning of the encrypted file.
 */
[[nodiscard]] CipherStatus cipher_encrypt_begin(const unsigned char key[CIPHER_KEY_BYTES],
                                                CipherStream **stream,
                                                unsigned char header[CIPHER_HEADER_BYTES]);

/**
 * @brief Encrypts the next chunk.
 *
 * @param stream  State from cipher_encrypt_begin().
 * @param in      Plaintext chunk (may be NULL only if @p in_len is 0).
 * @param in_len  At most CIPHER_CHUNK_SIZE. Must equal CIPHER_CHUNK_SIZE for
 *                every chunk except the last.
 * @param last    true for the final chunk of the file.
 * @param out     Output buffer of at least in_len + CIPHER_TAG_BYTES bytes.
 * @param out_len Receives in_len + CIPHER_TAG_BYTES.
 */
[[nodiscard]] CipherStatus cipher_encrypt_chunk(CipherStream *stream,
                                                const unsigned char *in, size_t in_len, bool last,
                                                unsigned char *out, size_t *out_len);

/**
 * @brief Starts decrypting, from the header read at the start of the file.
 *
 * @param key    CIPHER_KEY_BYTES-byte key.
 * @param header The first CIPHER_HEADER_BYTES bytes of the encrypted file.
 * @param stream Receives the state. Release it with cipher_stream_free().
 * @return CIPHER_OK, CIPHER_ERR_FORMAT or CIPHER_ERR_VERSION for files that
 *         are not valid sfm files.
 */
[[nodiscard]] CipherStatus cipher_decrypt_begin(const unsigned char key[CIPHER_KEY_BYTES],
                                                const unsigned char header[CIPHER_HEADER_BYTES],
                                                CipherStream **stream);

/**
 * @brief Decrypts the next chunk and verifies it.
 *
 * Nothing is returned for a chunk that fails verification. After a failure
 * the stream must be abandoned.
 *
 * @param stream  State from cipher_decrypt_begin().
 * @param in      Encrypted chunk, as read from the file.
 * @param in_len  Between CIPHER_TAG_BYTES and CIPHER_CHUNK_SIZE + CIPHER_TAG_BYTES.
 * @param out     Output buffer of at least CIPHER_CHUNK_SIZE bytes.
 * @param out_len Receives the plaintext length.
 * @param last    Receives true if this was the final chunk.
 * @return CIPHER_OK, or CIPHER_ERR_AUTH for a wrong key, modified, reordered
 *         or truncated data.
 */
[[nodiscard]] CipherStatus cipher_decrypt_chunk(CipherStream *stream,
                                                const unsigned char *in, size_t in_len,
                                                unsigned char *out, size_t *out_len, bool *last);

/** Wipes and frees a stream state. Safe to call with NULL. */
void cipher_stream_free(CipherStream *stream);

/**
 * @brief Returns the exact size of the encrypted file for a given plaintext size.
 *
 * Header + plaintext + one 17-byte tag per chunk. An empty file still has one
 * (empty) chunk. Valid for sizes up to FILEIO_MAX_SIZE.
 */
[[nodiscard]] uint64_t cipher_encrypted_size(uint64_t plain_size);

/** Wipes a buffer with zeros and frees it. Safe to call with NULL. */
void cipher_free(unsigned char *buf, size_t len);

/** Returns a human-readable message for a CipherStatus (never NULL). */
[[nodiscard]] const char *cipher_strerror(CipherStatus status);

#endif