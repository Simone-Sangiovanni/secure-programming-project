#include "cipher.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC                 "SFM1"
#define MAGIC_LEN             4U
#define FORMAT_VERSION        1U
#define VERSION_OFFSET        MAGIC_LEN
#define AD_LEN                (MAGIC_LEN + 1U)  // magic + version: authenticated, not encrypted
#define STREAM_HEADER_OFFSET  AD_LEN
#define STREAM_HEADER_BYTES   crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define CIPHERTEXT_OFFSET     (STREAM_HEADER_OFFSET + STREAM_HEADER_BYTES)
#define TAG_BYTES             crypto_secretstream_xchacha20poly1305_ABYTES
#define OVERHEAD              (CIPHERTEXT_OFFSET + TAG_BYTES)  // output size minus input size

static_assert(CIPHER_KEY_BYTES == crypto_secretstream_xchacha20poly1305_KEYBYTES,
              "key size mismatch");

CipherStatus cipher_encrypt(const unsigned char key[CIPHER_KEY_BYTES],
                            const unsigned char *in, size_t in_len,
                            unsigned char **out, size_t *out_len) {
    if (key == nullptr || (in == nullptr && in_len > 0) || out == nullptr || out_len == nullptr) {
        return CIPHER_ERR_ARGS;
    }
    if (in_len > SIZE_MAX - OVERHEAD) return CIPHER_ERR_TOO_BIG;
    if (sodium_init() < 0) return CIPHER_ERR_INIT;

    const size_t total = OVERHEAD + in_len;
    unsigned char *buf = malloc(total);
    if (buf == nullptr) return CIPHER_ERR_ALLOC;

    memcpy(buf, MAGIC, MAGIC_LEN);
    buf[VERSION_OFFSET] = (unsigned char)FORMAT_VERSION;

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_push(&state, buf + STREAM_HEADER_OFFSET, key) != 0) {
        free(buf);
        return CIPHER_ERR_ENCRYPT;
    }

    // The whole file is ONE message, marked as the final one (TAG_FINAL), so
    // that a truncated file is detected when decrypting.
    unsigned long long clen = 0;
    const int rc = crypto_secretstream_xchacha20poly1305_push(
        &state, buf + CIPHERTEXT_OFFSET, &clen, in, in_len,
        buf, AD_LEN, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    sodium_memzero(&state, sizeof state);

    if (rc != 0 || clen != in_len + TAG_BYTES) {
        free(buf);
        return CIPHER_ERR_ENCRYPT;
    }

    *out = buf;
    *out_len = total;
    return CIPHER_OK;
}

CipherStatus cipher_decrypt(const unsigned char key[CIPHER_KEY_BYTES],
                            const unsigned char *in, size_t in_len,
                            unsigned char **out, size_t *out_len) {
    if (key == nullptr || in == nullptr || out == nullptr || out_len == nullptr) {
        return CIPHER_ERR_ARGS;
    }
    if (sodium_init() < 0) return CIPHER_ERR_INIT;

    if (in_len < OVERHEAD || memcmp(in, MAGIC, MAGIC_LEN) != 0) return CIPHER_ERR_FORMAT;
    if (in[VERSION_OFFSET] != FORMAT_VERSION) return CIPHER_ERR_VERSION;

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, in + STREAM_HEADER_OFFSET, key) != 0) {
        return CIPHER_ERR_FORMAT;  // invalid stream header
    }

    const size_t plain_len = in_len - OVERHEAD;
    unsigned char *plain = malloc(plain_len > 0 ? plain_len : 1);  // never malloc(0)
    if (plain == nullptr) {
        sodium_memzero(&state, sizeof state);
        return CIPHER_ERR_ALLOC;
    }

    unsigned long long mlen = 0;
    unsigned char tag = 0;
    const int rc = crypto_secretstream_xchacha20poly1305_pull(
        &state, plain, &mlen, &tag, in + CIPHERTEXT_OFFSET, in_len - CIPHERTEXT_OFFSET,
        in, AD_LEN);
    sodium_memzero(&state, sizeof state);

    // Must be the final message; otherwise the file was cut or extended.
    if (rc != 0 || tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL || mlen != plain_len) {
        cipher_free(plain, plain_len);
        return CIPHER_ERR_AUTH;
    }

    *out = plain;
    *out_len = plain_len;
    return CIPHER_OK;
}

void cipher_free(unsigned char *buf, size_t len) {
    if (buf == nullptr) return;
    sodium_memzero(buf, len);
    free(buf);
}

const char *cipher_strerror(CipherStatus status) {
    switch (status) {
        case CIPHER_OK:          return "ok";
        case CIPHER_ERR_ARGS:    return "invalid arguments (internal error)";
        case CIPHER_ERR_INIT:    return "cannot initialise libsodium";
        case CIPHER_ERR_ALLOC:   return "out of memory";
        case CIPHER_ERR_TOO_BIG: return "input too large";
        case CIPHER_ERR_ENCRYPT: return "encryption failed";
        case CIPHER_ERR_FORMAT:  return "not a valid sfm encrypted file";
        case CIPHER_ERR_VERSION: return "unsupported file format version";
        case CIPHER_ERR_AUTH:    return "wrong key, or the file was modified or corrupted";
    }
    return "unknown error";
}