#include "filecrypt.h"

#include <sodium.h>
#include <stdlib.h>

#define ENC_CHUNK_MAX (CIPHER_CHUNK_SIZE + CIPHER_TAG_BYTES)

typedef struct {
    FileReader *in;
    FileWriter *out;
    CipherStream *stream;
    unsigned char *plain;
    unsigned char *enc;
} CryptCtx;

static FileCryptResult io_err(FileIoStatus st, bool on_out) {
    return (FileCryptResult){.io = st, .cipher = CIPHER_OK, .io_on_output = on_out};
}

static FileCryptResult cipher_err(CipherStatus st) {
    return (FileCryptResult){.io = FILEIO_OK, .cipher = st, .io_on_output = false};
}

static bool alloc_buffers(CryptCtx *ctx) {
    // Plaintext buffer lives in locked, guard-page-protected memory.
    ctx->plain = sodium_malloc(CIPHER_CHUNK_SIZE);
    ctx->enc = malloc(ENC_CHUNK_MAX);
    return ctx->plain != nullptr && ctx->enc != nullptr;
}

static void cleanup(CryptCtx *ctx) {
    fileio_writer_abort(ctx->out);
    cipher_stream_free(ctx->stream);
    sodium_free(ctx->plain);
    cipher_free(ctx->enc, ENC_CHUNK_MAX);
    fileio_reader_close(ctx->in);
}

bool filecrypt_ok(FileCryptResult result) {
    return result.io == FILEIO_OK && result.cipher == CIPHER_OK;
}

FileCryptResult filecrypt_encrypt(const unsigned char kek[CIPHER_KEY_BYTES],
                                  const char *in_path, const char *out_path) {
    if (kek == nullptr || in_path == nullptr || out_path == nullptr) return cipher_err(CIPHER_ERR_ARGS);

    CryptCtx ctx = {};
    FileCryptResult res = {FILEIO_OK, CIPHER_OK, false};
    unsigned char header[CIPHER_HEADER_BYTES];
    uint64_t remaining = 0;

    FileIoStatus fs = fileio_reader_open(in_path, &ctx.in, &remaining);
    if (fs != FILEIO_OK) { res = io_err(fs, false); goto done; }
    if (cipher_encrypted_size(remaining) > FILEIO_MAX_SIZE) { res = io_err(FILEIO_ERR_TOO_BIG, true); goto done; }
    if (!alloc_buffers(&ctx)) { res = io_err(FILEIO_ERR_ALLOC, false); goto done; }

    CipherStatus cs = cipher_encrypt_begin(kek, &ctx.stream, header);
    if (cs != CIPHER_OK) { res = cipher_err(cs); goto done; }

    if ((fs = fileio_writer_create(out_path, &ctx.out)) != FILEIO_OK ||
        (fs = fileio_writer_write(ctx.out, header, sizeof header)) != FILEIO_OK) {
        res = io_err(fs, true);
        goto done;
    }

    for (bool last = false; !last;) {
        const size_t want = remaining < CIPHER_CHUNK_SIZE ? (size_t)remaining : CIPHER_CHUNK_SIZE;
        size_t got = 0, enc_len = 0;

        if ((fs = fileio_reader_read(ctx.in, ctx.plain, want, &got)) != FILEIO_OK) {
            res = io_err(fs, false);
            goto done;
        }
        if (got != want) { res = io_err(FILEIO_ERR_READ, false); goto done; }

        remaining -= want;
        last = (remaining == 0);

        if ((cs = cipher_encrypt_chunk(ctx.stream, ctx.plain, want, last, ctx.enc, &enc_len)) != CIPHER_OK) {
            res = cipher_err(cs);
            goto done;
        }
        if ((fs = fileio_writer_write(ctx.out, ctx.enc, enc_len)) != FILEIO_OK) {
            res = io_err(fs, true);
            goto done;
        }
    }

    fs = fileio_writer_finish(ctx.out);
    ctx.out = nullptr;
    if (fs != FILEIO_OK) res = io_err(fs, true);

done:
    cleanup(&ctx);
    return res;
}

FileCryptResult filecrypt_decrypt(const unsigned char kek[CIPHER_KEY_BYTES],
                                  const char *in_path, const char *out_path) {
    if (kek == nullptr || in_path == nullptr || out_path == nullptr) return cipher_err(CIPHER_ERR_ARGS);

    CryptCtx ctx = {};
    FileCryptResult res = {FILEIO_OK, CIPHER_OK, false};
    unsigned char header[CIPHER_HEADER_BYTES];
    uint64_t ignored = 0;
    size_t got = 0;

    FileIoStatus fs = fileio_reader_open(in_path, &ctx.in, &ignored);
    if (fs != FILEIO_OK) { res = io_err(fs, false); goto done; }

    // Validate header before creating any output file.
    if ((fs = fileio_reader_read(ctx.in, header, sizeof header, &got)) != FILEIO_OK) {
        res = io_err(fs, false);
        goto done;
    }
    if (got != sizeof header) { res = cipher_err(CIPHER_ERR_FORMAT); goto done; }

    CipherStatus cs = cipher_decrypt_begin(kek, header, &ctx.stream);
    if (cs != CIPHER_OK) { res = cipher_err(cs); goto done; }
    if (!alloc_buffers(&ctx)) { res = io_err(FILEIO_ERR_ALLOC, false); goto done; }
    if ((fs = fileio_writer_create(out_path, &ctx.out)) != FILEIO_OK) { res = io_err(fs, true); goto done; }

    for (bool last = false; !last;) {
        size_t plain_len = 0;
        if ((fs = fileio_reader_read(ctx.in, ctx.enc, ENC_CHUNK_MAX, &got)) != FILEIO_OK) {
            res = io_err(fs, false);
            goto done;
        }
        if ((cs = cipher_decrypt_chunk(ctx.stream, ctx.enc, got, ctx.plain, &plain_len, &last)) != CIPHER_OK ||
            (!last && got != ENC_CHUNK_MAX)) {
            res = cipher_err(cs != CIPHER_OK ? cs : CIPHER_ERR_AUTH);
            goto done;
        }
        if ((fs = fileio_writer_write(ctx.out, ctx.plain, plain_len)) != FILEIO_OK) {
            res = io_err(fs, true);
            goto done;
        }
    }

    // Reject trailing bytes after the FINAL chunk.
    unsigned char extra = 0;
    size_t trailing = 0;
    if ((fs = fileio_reader_read(ctx.in, &extra, 1, &trailing)) != FILEIO_OK) {
        res = io_err(fs, false);
        goto done;
    }
    if (trailing != 0) { res = cipher_err(CIPHER_ERR_AUTH); goto done; }

    fs = fileio_writer_finish(ctx.out);
    ctx.out = nullptr;
    if (fs != FILEIO_OK) res = io_err(fs, true);

done:
    cleanup(&ctx);
    return res;
}