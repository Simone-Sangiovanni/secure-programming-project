#ifndef SFM_CIPHER_H
#define SFM_CIPHER_H

#include <stddef.h>
#include <stdint.h>

#define CIPHER_CHUNK_SIZE   131072U  // 128 KiB plaintext per chunk
#define CIPHER_TAG_BYTES    17U      // Per-chunk authentication tag size
#define CIPHER_HEADER_BYTES 101U     // "SFM1"(4) | ver=3(1) | nonce(24) | wrapped_dek(48) | stream_hdr(24)
#define CIPHER_KEY_BYTES    32       // KEK and per-file DEK size in bytes

typedef enum {
    CIPHER_OK = 0,
    CIPHER_ERR_ARGS,
    CIPHER_ERR_INIT,
    CIPHER_ERR_ALLOC,
    CIPHER_ERR_TOO_BIG,
    CIPHER_ERR_ENCRYPT,
    CIPHER_ERR_FORMAT,
    CIPHER_ERR_VERSION,
    CIPHER_ERR_AUTH
} CipherStatus;

typedef struct CipherStream CipherStream;

[[nodiscard]] CipherStatus cipher_encrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                                CipherStream **stream,
                                                unsigned char header[CIPHER_HEADER_BYTES]);
[[nodiscard]] CipherStatus cipher_encrypt_chunk(CipherStream *stream,
                                                const unsigned char *in, size_t in_len, bool last,
                                                unsigned char *out, size_t *out_len);
[[nodiscard]] CipherStatus cipher_decrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                                const unsigned char header[CIPHER_HEADER_BYTES],
                                                CipherStream **stream);
[[nodiscard]] CipherStatus cipher_decrypt_chunk(CipherStream *stream,
                                                const unsigned char *in, size_t in_len,
                                                unsigned char *out, size_t *out_len, bool *last);
void cipher_stream_free(CipherStream *stream);
[[nodiscard]] uint64_t cipher_encrypted_size(uint64_t plain_size);
void cipher_free(unsigned char *buf, size_t len);
[[nodiscard]] const char *cipher_strerror(CipherStatus status);

#endif