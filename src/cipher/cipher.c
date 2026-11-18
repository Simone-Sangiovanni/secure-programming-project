#include "cipher.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC                "SFM1"
#define MAGIC_LEN            4U
#define FORMAT_VERSION       3U
#define VERSION_OFFSET       MAGIC_LEN
#define AD_LEN               (MAGIC_LEN + 1U)  // magic + version: authenticated, not encrypted

#define WRAP_NONCE_BYTES     crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  // 24
#define WRAPPED_DEK_BYTES    (CIPHER_KEY_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)  // 32 + 16 = 48

#define WRAP_NONCE_OFFSET    AD_LEN                                        // 5
#define WRAPPED_DEK_OFFSET   (WRAP_NONCE_OFFSET + WRAP_NONCE_BYTES)        // 29
#define STREAM_HEADER_OFFSET (WRAPPED_DEK_OFFSET + WRAPPED_DEK_BYTES)      // 77

static_assert(CIPHER_KEY_BYTES == crypto_secretstream_xchacha20poly1305_KEYBYTES,
              "stream key size mismatch");
static_assert(CIPHER_KEY_BYTES == crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
              "AEAD KEK size mismatch");
static_assert(CIPHER_CHUNK_SIZE == 128 * 1024, "the chunk size must be 128 KiB");
static_assert(CIPHER_TAG_BYTES == crypto_secretstream_xchacha20poly1305_ABYTES,
              "tag size mismatch");
static_assert(CIPHER_HEADER_BYTES == STREAM_HEADER_OFFSET + crypto_secretstream_xchacha20poly1305_HEADERBYTES,
              "header size mismatch (expected 101 bytes)");

struct CipherStream {
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char ad[AD_LEN];  // magic + version, authenticated with every chunk
};

void cipher_stream_free(CipherStream *stream) {
    if (stream == nullptr) return;
    sodium_memzero(stream, sizeof *stream);  // the state contains key material
    sodium_free(stream);
}

CipherStatus cipher_encrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                  CipherStream **stream,
                                  unsigned char header[CIPHER_HEADER_BYTES]) {
    if (kek == nullptr || stream == nullptr || header == nullptr) return CIPHER_ERR_ARGS;
    if (sodium_init() < 0) return CIPHER_ERR_INIT;

    // Allocate CipherStream in locked, guard-page-protected memory so stream key state cannot swap.
    CipherStream *s = sodium_malloc(sizeof *s);
    if (s == nullptr) return CIPHER_ERR_ALLOC;

    memcpy(header, MAGIC, MAGIC_LEN);
    header[VERSION_OFFSET] = (unsigned char)FORMAT_VERSION;
    memcpy(s->ad, header, AD_LEN);

    // 1. Generate a fresh 32-byte per-file DEK (locked in RAM) and a 24-byte wrap nonce.
    unsigned char dek[CIPHER_KEY_BYTES];
    if (sodium_mlock(dek, sizeof dek) != 0) {
        cipher_stream_free(s);
        return CIPHER_ERR_ALLOC;
    }
    randombytes_buf(dek, sizeof dek);
    randombytes_buf(header + WRAP_NONCE_OFFSET, WRAP_NONCE_BYTES);

    // 2. Wrap the DEK under the KEK, binding the 5-byte prefix (magic + version) as AD.
    unsigned long long wrapped_len = 0;
    const int wrap_rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        header + WRAPPED_DEK_OFFSET, &wrapped_len,
        dek, sizeof dek,
        s->ad, AD_LEN,
        nullptr,
        header + WRAP_NONCE_OFFSET,
        kek);

    if (wrap_rc != 0 || wrapped_len != WRAPPED_DEK_BYTES) {
        sodium_memzero(dek, sizeof dek);
        (void)sodium_munlock(dek, sizeof dek);
        cipher_stream_free(s);
        return CIPHER_ERR_ENCRYPT;
    }

    // 3. Initialize secretstream with the per-file DEK (writes 24-byte stream header at offset 77).
    const int init_rc = crypto_secretstream_xchacha20poly1305_init_push(
        &s->state, header + STREAM_HEADER_OFFSET, dek);
    sodium_memzero(dek, sizeof dek);
    (void)sodium_munlock(dek, sizeof dek);

    if (init_rc != 0) {
        cipher_stream_free(s);
        return CIPHER_ERR_ENCRYPT;
    }

    *stream = s;
    return CIPHER_OK;
}

CipherStatus cipher_encrypt_chunk(CipherStream *stream,
                                  const unsigned char *in, size_t in_len, bool last,
                                  unsigned char *out, size_t *out_len) {
    if (stream == nullptr || (in == nullptr && in_len > 0) || out == nullptr || out_len == nullptr) {
        return CIPHER_ERR_ARGS;
    }
    if (in_len > CIPHER_CHUNK_SIZE) return CIPHER_ERR_TOO_BIG;

    const unsigned char tag = last ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
                                   : crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    unsigned long long clen = 0;
    const int rc = crypto_secretstream_xchacha20poly1305_push(
        &stream->state, out, &clen, in, in_len, stream->ad, AD_LEN, tag);

    if (rc != 0 || clen != in_len + CIPHER_TAG_BYTES) return CIPHER_ERR_ENCRYPT;
    *out_len = (size_t)clen;
    return CIPHER_OK;
}

CipherStatus cipher_decrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                  const unsigned char header[CIPHER_HEADER_BYTES],
                                  CipherStream **stream) {
    if (kek == nullptr || header == nullptr || stream == nullptr) return CIPHER_ERR_ARGS;
    if (sodium_init() < 0) return CIPHER_ERR_INIT;

    if (memcmp(header, MAGIC, MAGIC_LEN) != 0) return CIPHER_ERR_FORMAT;
    if (header[VERSION_OFFSET] != FORMAT_VERSION) return CIPHER_ERR_VERSION;

    CipherStream *s = sodium_malloc(sizeof *s);
    if (s == nullptr) return CIPHER_ERR_ALLOC;
    memcpy(s->ad, header, AD_LEN);

    // 1. Unwrap the per-file DEK using the KEK (locked in RAM) and verify its 16-byte Poly1305 tag.
    unsigned char dek[CIPHER_KEY_BYTES];
    if (sodium_mlock(dek, sizeof dek) != 0) {
        cipher_stream_free(s);
        return CIPHER_ERR_ALLOC;
    }
    unsigned long long dek_len = 0;
    const int unwrap_rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        dek, &dek_len,
        nullptr,
        header + WRAPPED_DEK_OFFSET, WRAPPED_DEK_BYTES,
        s->ad, AD_LEN,
        header + WRAP_NONCE_OFFSET,
        kek);

    if (unwrap_rc != 0 || dek_len != sizeof dek) {
        sodium_memzero(dek, sizeof dek);
        (void)sodium_munlock(dek, sizeof dek);
        cipher_stream_free(s);
        return CIPHER_ERR_AUTH;
    }

    // 2. Initialize secretstream decryption with the unwrapped DEK.
    const int init_rc = crypto_secretstream_xchacha20poly1305_init_pull(
        &s->state, header + STREAM_HEADER_OFFSET, dek);
    sodium_memzero(dek, sizeof dek);
    (void)sodium_munlock(dek, sizeof dek);

    if (init_rc != 0) {
        cipher_stream_free(s);
        return CIPHER_ERR_FORMAT;  // invalid stream header
    }

    *stream = s;
    return CIPHER_OK;
}

CipherStatus cipher_decrypt_chunk(CipherStream *stream,
                                  const unsigned char *in, size_t in_len,
                                  unsigned char *out, size_t *out_len, bool *last) {
    if (stream == nullptr || in == nullptr || out == nullptr || out_len == nullptr || last == nullptr) {
        return CIPHER_ERR_ARGS;
    }
    if (in_len > CIPHER_CHUNK_SIZE + CIPHER_TAG_BYTES) return CIPHER_ERR_ARGS;
    if (in_len < CIPHER_TAG_BYTES) return CIPHER_ERR_AUTH;  // too short to be a chunk: file was cut

    unsigned long long mlen = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(&stream->state, out, &mlen, &tag,
                                                   in, in_len, stream->ad, AD_LEN) != 0) {
        return CIPHER_ERR_AUTH;
    }

    // Only the two tags this program produces are acceptable.
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        *last = true;
    } else if (tag == crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
        *last = false;
    } else {
        return CIPHER_ERR_AUTH;
    }

    *out_len = (size_t)mlen;
    return CIPHER_OK;
}

uint64_t cipher_encrypted_size(uint64_t plain_size) {
    const uint64_t chunks = (plain_size == 0) ? 1 : (plain_size - 1) / CIPHER_CHUNK_SIZE + 1;
    return CIPHER_HEADER_BYTES + plain_size + chunks * CIPHER_TAG_BYTES;
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
        case CIPHER_ERR_TOO_BIG: return "chunk too large (internal error)";
        case CIPHER_ERR_ENCRYPT: return "encryption failed";
        case CIPHER_ERR_FORMAT:  return "not a valid sfm encrypted file";
        case CIPHER_ERR_VERSION: return "unsupported file format version";
        case CIPHER_ERR_AUTH:    return "wrong key, or the file was modified, corrupted or truncated";
    }
    return "unknown error";
}
