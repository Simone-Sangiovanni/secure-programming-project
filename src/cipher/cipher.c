#include "cipher.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC                "SFM1"
#define MAGIC_LEN            4U
#define FORMAT_VERSION       3U
#define AD_LEN               (MAGIC_LEN + 1U)

#define WRAP_NONCE_BYTES     crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define WRAPPED_DEK_BYTES    (CIPHER_KEY_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)

#define WRAP_NONCE_OFFSET    AD_LEN
#define WRAPPED_DEK_OFFSET   (WRAP_NONCE_OFFSET + WRAP_NONCE_BYTES)
#define STREAM_HEADER_OFFSET (WRAPPED_DEK_OFFSET + WRAPPED_DEK_BYTES)

static_assert(CIPHER_KEY_BYTES == crypto_secretstream_xchacha20poly1305_KEYBYTES, "stream key size mismatch");
static_assert(CIPHER_KEY_BYTES == crypto_aead_xchacha20poly1305_ietf_KEYBYTES, "AEAD KEK size mismatch");
static_assert(CIPHER_CHUNK_SIZE == 128 * 1024, "chunk size must be 128 KiB");
static_assert(CIPHER_TAG_BYTES == crypto_secretstream_xchacha20poly1305_ABYTES, "tag size mismatch");
static_assert(CIPHER_HEADER_BYTES == STREAM_HEADER_OFFSET + crypto_secretstream_xchacha20poly1305_HEADERBYTES,
              "header size must be 101 bytes");

struct CipherStream {
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char ad[AD_LEN];
};

static CipherStream *stream_open(const unsigned char ad[AD_LEN], unsigned char dek[CIPHER_KEY_BYTES]) {
    CipherStream *s = sodium_malloc(sizeof *s);
    if (s == nullptr) return nullptr;
    if (sodium_mlock(dek, CIPHER_KEY_BYTES) != 0) {
        cipher_stream_free(s);
        return nullptr;
    }
    memcpy(s->ad, ad, AD_LEN);
    return s;
}

static void dek_wipe_unlock(unsigned char dek[CIPHER_KEY_BYTES]) {
    sodium_memzero(dek, CIPHER_KEY_BYTES);
    (void)sodium_munlock(dek, CIPHER_KEY_BYTES);
}

void cipher_stream_free(CipherStream *stream) {
    if (stream == nullptr) return;
    sodium_memzero(stream, sizeof *stream);
    sodium_free(stream);
}

CipherStatus cipher_encrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                  CipherStream **stream,
                                  unsigned char header[CIPHER_HEADER_BYTES]) {
    if (kek == nullptr || stream == nullptr || header == nullptr) return CIPHER_ERR_ARGS;
    if (sodium_init() < 0) return CIPHER_ERR_INIT;

    memcpy(header, MAGIC, MAGIC_LEN);
    header[MAGIC_LEN] = (unsigned char)FORMAT_VERSION;

    unsigned char dek[CIPHER_KEY_BYTES];
    CipherStream *s = stream_open(header, dek);
    if (s == nullptr) return CIPHER_ERR_ALLOC;

    CipherStatus status = CIPHER_ERR_ENCRYPT;
    randombytes_buf(dek, sizeof dek);
    randombytes_buf(header + WRAP_NONCE_OFFSET, WRAP_NONCE_BYTES);

    unsigned long long wrapped_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(header + WRAPPED_DEK_OFFSET, &wrapped_len,
                                                   dek, sizeof dek, s->ad, AD_LEN,
                                                   nullptr, header + WRAP_NONCE_OFFSET, kek) == 0 &&
        wrapped_len == WRAPPED_DEK_BYTES &&
        crypto_secretstream_xchacha20poly1305_init_push(&s->state, header + STREAM_HEADER_OFFSET, dek) == 0) {
        *stream = s;
        s = nullptr;
        status = CIPHER_OK;
    }

    dek_wipe_unlock(dek);
    cipher_stream_free(s);
    return status;
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
    if (crypto_secretstream_xchacha20poly1305_push(&stream->state, out, &clen, in, in_len,
                                                  stream->ad, AD_LEN, tag) != 0 ||
        clen != in_len + CIPHER_TAG_BYTES) {
        return CIPHER_ERR_ENCRYPT;
    }
    *out_len = (size_t)clen;
    return CIPHER_OK;
}

CipherStatus cipher_decrypt_begin(const unsigned char kek[CIPHER_KEY_BYTES],
                                  const unsigned char header[CIPHER_HEADER_BYTES],
                                  CipherStream **stream) {
    if (kek == nullptr || header == nullptr || stream == nullptr) return CIPHER_ERR_ARGS;
    if (sodium_init() < 0) return CIPHER_ERR_INIT;
    if (memcmp(header, MAGIC, MAGIC_LEN) != 0) return CIPHER_ERR_FORMAT;
    if (header[MAGIC_LEN] != FORMAT_VERSION) return CIPHER_ERR_VERSION;

    unsigned char dek[CIPHER_KEY_BYTES];
    CipherStream *s = stream_open(header, dek);
    if (s == nullptr) return CIPHER_ERR_ALLOC;

    CipherStatus status = CIPHER_ERR_AUTH;
    unsigned long long dek_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(dek, &dek_len, nullptr,
                                                   header + WRAPPED_DEK_OFFSET, WRAPPED_DEK_BYTES,
                                                   s->ad, AD_LEN, header + WRAP_NONCE_OFFSET, kek) == 0 &&
        dek_len == sizeof dek) {
        if (crypto_secretstream_xchacha20poly1305_init_pull(&s->state, header + STREAM_HEADER_OFFSET, dek) == 0) {
            *stream = s;
            s = nullptr;
            status = CIPHER_OK;
        } else {
            status = CIPHER_ERR_FORMAT;
        }
    }

    dek_wipe_unlock(dek);
    cipher_stream_free(s);
    return status;
}

CipherStatus cipher_decrypt_chunk(CipherStream *stream,
                                  const unsigned char *in, size_t in_len,
                                  unsigned char *out, size_t *out_len, bool *last) {
    if (stream == nullptr || in == nullptr || out == nullptr || out_len == nullptr || last == nullptr) {
        return CIPHER_ERR_ARGS;
    }
    if (in_len > CIPHER_CHUNK_SIZE + CIPHER_TAG_BYTES) return CIPHER_ERR_ARGS;
    if (in_len < CIPHER_TAG_BYTES) return CIPHER_ERR_AUTH;

    unsigned long long mlen = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(&stream->state, out, &mlen, &tag,
                                                   in, in_len, stream->ad, AD_LEN) != 0) {
        return CIPHER_ERR_AUTH;
    }
    if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL &&
        tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
        return CIPHER_ERR_AUTH;
    }

    *last = (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);
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
    static const char *const messages[] = {
        [CIPHER_OK]          = "ok",
        [CIPHER_ERR_ARGS]    = "invalid arguments (internal error)",
        [CIPHER_ERR_INIT]    = "cannot initialise libsodium",
        [CIPHER_ERR_ALLOC]   = "out of memory",
        [CIPHER_ERR_TOO_BIG] = "chunk too large (internal error)",
        [CIPHER_ERR_ENCRYPT] = "encryption failed",
        [CIPHER_ERR_FORMAT]  = "not a valid sfm encrypted file",
        [CIPHER_ERR_VERSION] = "unsupported file format version",
        [CIPHER_ERR_AUTH]    = "wrong key, or the file was modified, corrupted or truncated",
    };
    if ((unsigned)status < sizeof messages / sizeof messages[0] && messages[status] != nullptr) {
        return messages[status];
    }
    return "unknown error";
}
