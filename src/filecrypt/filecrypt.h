#ifndef SFM_FILECRYPT_H
#define SFM_FILECRYPT_H

#include "../cipher/cipher.h"
#include "../fileio/fileio.h"

/**
 * @file filecrypt.h
 * @brief Encrypts / decrypts a whole file, chunk by chunk (file -> file).
 *
 * Glue between fileio (disk) and cipher (crypto). Memory use is about
 * 2 * CIPHER_CHUNK_SIZE (256 KiB) no matter how large the file is.
 */

/** Outcome of an operation: which layer failed, and why. */
typedef struct {
    FileIoStatus io;       /**< FILEIO_OK unless a file operation failed. */
    CipherStatus cipher;   /**< CIPHER_OK unless the cryptography failed. */
    bool io_on_output;     /**< true if @c io refers to the output file, false for the input. */
} FileCryptResult;

/** Returns true if the operation succeeded. */
[[nodiscard]] bool filecrypt_ok(FileCryptResult result);

/**
 * @brief Encrypts @p in_path into the NEW file @p out_path.
 *
 * Fails up front if the input, or the encrypted output (input + overhead),
 * would exceed FILEIO_MAX_SIZE. If anything fails, the output file is
 * removed. The input is never modified.
 */
[[nodiscard]] FileCryptResult filecrypt_encrypt(const unsigned char key[CIPHER_KEY_BYTES],
                                                const char *in_path, const char *out_path);

/**
 * @brief Decrypts @p in_path into the NEW file @p out_path.
 *
 * The plaintext is written chunk by chunk as each chunk is verified. If a
 * later chunk fails verification (wrong key, tampering, truncation, trailing
 * data), the output file is removed, so a failed decryption leaves nothing
 * behind. The input is never modified.
 */
[[nodiscard]] FileCryptResult filecrypt_decrypt(const unsigned char key[CIPHER_KEY_BYTES],
                                                const char *in_path, const char *out_path);

#endif
