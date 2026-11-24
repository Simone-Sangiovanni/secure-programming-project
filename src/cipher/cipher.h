#ifndef SFM_CIPHER_H
#define SFM_CIPHER_H

#include <stddef.h>
#include <stdint.h>

/**
 * @file cipher.h
 * @brief Chunked authenticated encryption (XChaCha20-Poly1305 secretstream)
 *        with per-file Data-Encryption Keys (DEKs).
 *
 * File layout (version 3, 101-byte header):
 *   "SFM1" (4) | version=3 (1) | wrap_nonce (24) | wrapped_dek (48) | stream_header (24) | chunks...
 *
 * The 5-byte prefix ("SFM1" || 3) is bound as associated data to both the
 * wrapped DEK and every chunk. Each chunk holds up to CIPHER_CHUNK_SIZE
 * plaintext bytes followed by a CIPHER_TAG_BYTES authentication tag.
 */

#define CIPHER_CHUNK_SIZE   131072U  /**< 128 KiB plaintext per chunk (plain literal avoids widening warnings). */
#define CIPHER_TAG_BYTES    17U      /**< Per-chunk authentication tag size. */
#define CIPHER_HEADER_BYTES 101U     /**< Encrypted file header size. */
#define CIPHER_KEY_BYTES    32       /**< KEK and per-file DEK size in bytes. */

typedef enum {
    CIPHER_OK = 0,        /**< Success. */
    CIPHER_ERR_ARGS,      /**< NULL pointer or invalid buffer size. */
    CIPHER_ERR_INIT,      /**< libsodium initialization failed. */
    CIPHER_ERR_ALLOC,     /**< Memory allocation or mlock failed. */
    CIPHER_ERR_TOO_BIG,   /**< Plaintext chunk exceeds CIPHER_CHUNK_SIZE. */
    CIPHER_ERR_ENCRYPT,   /**< Encryption operation failed. */
    CIPHER_ERR_FORMAT,    /**< Invalid file magic or stream header. */
    CIPHER_ERR_VERSION,   /**< Unsupported file format version. */
    CIPHER_ERR_AUTH       /**< Wrong key, or data modified/corrupted/truncated. */
} CipherStatus;

typedef struct CipherStream CipherStream;

/** Begins encrypting a file with a fresh per-file DEK wrapped under @p kek. */
[[nodiscard]] CipherStatus cipher_encrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                                CipherStream **stream,
                                                unsigned char header[CIPHER_HEADER_BYTES]);

/** Encrypts the next chunk (set @p last to true on the final chunk). */
[[nodiscard]] CipherStatus cipher_encrypt_chunk(CipherStream *stream,
                                                const unsigned char *in, size_t in_len, bool last,
                                                unsigned char *out, size_t *out_len);

/** Begins decrypting a file by validating @p header and unwrapping its DEK with @p kek. */
[[nodiscard]] CipherStatus cipher_decrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                                const unsigned char header[CIPHER_HEADER_BYTES],
                                                CipherStream **stream);

/** Decrypts and verifies the next chunk; sets @p last on the final chunk. */
[[nodiscard]] CipherStatus cipher_decrypt_chunk(CipherStream *stream,
                                                const unsigned char *in, size_t in_len,
                                                unsigned char *out, size_t *out_len, bool *last);

/** Zeroes and frees a stream state (safe with NULL). */
void cipher_stream_free(CipherStream *stream);

/** Returns the exact encrypted byte size for a plaintext of @p plain_size bytes. */
[[nodiscard]] uint64_t cipher_encrypted_size(uint64_t plain_size);

/** Zeroes @p len bytes of @p buf and frees it (safe with NULL). */
void cipher_free(unsigned char *buf, size_t len);

/** Returns a human-readable description for @p status (never NULL). */
[[nodiscard]] const char *cipher_strerror(CipherStatus status);

#endif
