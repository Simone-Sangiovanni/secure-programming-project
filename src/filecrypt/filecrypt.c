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

static FileCryptResult err_in(FileIoStatus status) {
    return (FileCryptResult){.io = status, .cipher = CIPHER_OK, .io_on_output = false};
}

static FileCryptResult err_out(FileIoStatus status) {
    return (FileCryptResult){.io = status, .cipher = CIPHER_OK, .io_on_output = true};
}

static FileCryptResult err_cipher(CipherStatus status) {
    return (FileCryptResult){.io = FILEIO_OK, .cipher = status, .io_on_output = false};
}

static bool alloc_buffers(CryptCtx *ctx) {
    // Keep plaintext in locked, guard-page-protected memory.
    ctx->plain = sodium_malloc(CIPHER_CHUNK_SIZE);
    ctx->enc = malloc(ENC_CHUNK_MAX);
    return ctx->plain != nullptr && ctx->enc != nullptr;
}

static void cleanup(CryptCtx *ctx) {
    fileio_writer_abort(ctx->out);   // no-op if finished; otherwise removes partial output
    cipher_stream_free(ctx->stream);
    sodium_free(ctx->plain);         // zeroes, unlocks, and frees locked plaintext buffer
    cipher_free(ctx->enc, ENC_CHUNK_MAX);
    fileio_reader_close(ctx->in);
}

bool filecrypt_ok(FileCryptResult result) {
    return result.io == FILEIO_OK && result.cipher == CIPHER_OK;
}

FileCryptResult filecrypt_encrypt(const unsigned char kek[CIPHER_KEY_BYTES],
                                  const char *in_path, const char *out_path) {
    if (kek == nullptr || in_path == nullptr || out_path == nullptr) {
        return err_cipher(CIPHER_ERR_ARGS);
    }

    CryptCtx ctx = {0};
    FileCryptResult res = {FILEIO_OK, CIPHER_OK, false};
    unsigned char header[CIPHER_HEADER_BYTES];
    uint64_t remaining = 0;

    FileIoStatus fs = fileio_reader_open(in_path, &ctx.in, &remaining);
    if (fs != FILEIO_OK) { res = err_in(fs); goto cleanup; }

    // Ensure the encrypted output (plaintext + framing overhead) also fits within FILEIO_MAX_SIZE.
    if (cipher_encrypted_size(remaining) > FILEIO_MAX_SIZE) {
        res = err_out(FILEIO_ERR_TOO_BIG);
        goto cleanup;
    }

    if (!alloc_buffers(&ctx)) { res = err_in(FILEIO_ERR_ALLOC); goto cleanup; }

    CipherStatus cs = cipher_encrypt_begin(kek, &ctx.stream, header);
    if (cs != CIPHER_OK) { res = err_cipher(cs); goto cleanup; }

    fs = fileio_writer_create(out_path, &ctx.out);
    if (fs != FILEIO_OK) { res = err_out(fs); goto cleanup; }

    fs = fileio_writer_write(ctx.out, header, sizeof header);
    if (fs != FILEIO_OK) { res = err_out(fs); goto cleanup; }

    bool last = false;
    while (!last) {
        const size_t want = remaining < CIPHER_CHUNK_SIZE ? (size_t)remaining : CIPHER_CHUNK_SIZE;
        size_t got = 0;

        fs = fileio_reader_read(ctx.in, ctx.plain, want, &got);
        if (fs != FILEIO_OK) { res = err_in(fs); goto cleanup; }
        if (got != want) { res = err_in(FILEIO_ERR_READ); goto cleanup; }  // file shrank mid-read

        remaining -= want;
        last = (remaining == 0);  // an empty file still produces one empty FINAL chunk

        size_t enc_len = 0;
        cs = cipher_encrypt_chunk(ctx.stream, ctx.plain, want, last, ctx.enc, &enc_len);
        if (cs != CIPHER_OK) { res = err_cipher(cs); goto cleanup; }

        fs = fileio_writer_write(ctx.out, ctx.enc, enc_len);
        if (fs != FILEIO_OK) { res = err_out(fs); goto cleanup; }
    }

    fs = fileio_writer_finish(ctx.out);  // consumes `ctx.out` regardless of outcome
    ctx.out = nullptr;
    if (fs != FILEIO_OK) { res = err_out(fs); }

cleanup:
    cleanup(&ctx);
    return res;
}

FileCryptResult filecrypt_decrypt(const unsigned char kek[CIPHER_KEY_BYTES],
                                  const char *in_path, const char *out_path) {
    if (kek == nullptr || in_path == nullptr || out_path == nullptr) {
        return err_cipher(CIPHER_ERR_ARGS);
    }

    CryptCtx ctx = {0};
    FileCryptResult res = {FILEIO_OK, CIPHER_OK, false};
    unsigned char header[CIPHER_HEADER_BYTES];
    uint64_t ignored_size = 0;
    size_t got = 0;

    FileIoStatus fs = fileio_reader_open(in_path, &ctx.in, &ignored_size);
    if (fs != FILEIO_OK) { res = err_in(fs); goto cleanup; }

    // Validate the header BEFORE creating any output file.
    fs = fileio_reader_read(ctx.in, header, sizeof header, &got);
    if (fs != FILEIO_OK) { res = err_in(fs); goto cleanup; }
    if (got != sizeof header) { res = err_cipher(CIPHER_ERR_FORMAT); goto cleanup; }

    CipherStatus cs = cipher_decrypt_begin(kek, header, &ctx.stream);
    if (cs != CIPHER_OK) { res = err_cipher(cs); goto cleanup; }

    if (!alloc_buffers(&ctx)) { res = err_in(FILEIO_ERR_ALLOC); goto cleanup; }

    fs = fileio_writer_create(out_path, &ctx.out);
    if (fs != FILEIO_OK) { res = err_out(fs); goto cleanup; }

    bool last = false;
    while (!last) {
        fs = fileio_reader_read(ctx.in, ctx.enc, ENC_CHUNK_MAX, &got);
        if (fs != FILEIO_OK) { res = err_in(fs); goto cleanup; }

        // If got == 0 (truncated stream without a FINAL chunk), cipher_decrypt_chunk fails auth.
        size_t plain_len = 0;
        cs = cipher_decrypt_chunk(ctx.stream, ctx.enc, got, ctx.plain, &plain_len, &last);
        if (cs != CIPHER_OK) { res = err_cipher(cs); goto cleanup; }

        // Every chunk before FINAL must be full-size.
        if (!last && got != ENC_CHUNK_MAX) { res = err_cipher(CIPHER_ERR_AUTH); goto cleanup; }

        fs = fileio_writer_write(ctx.out, ctx.plain, plain_len);
        if (fs != FILEIO_OK) { res = err_out(fs); goto cleanup; }
    }

    // Reject any trailing bytes after the FINAL chunk.
    unsigned char extra = 0;
    size_t trailing = 0;
    fs = fileio_reader_read(ctx.in, &extra, 1, &trailing);
    if (fs != FILEIO_OK) { res = err_in(fs); goto cleanup; }
    if (trailing != 0) { res = err_cipher(CIPHER_ERR_AUTH); goto cleanup; }

    fs = fileio_writer_finish(ctx.out);  // consumes `ctx.out` regardless of outcome
    ctx.out = nullptr;
    if (fs != FILEIO_OK) { res = err_out(fs); }

cleanup:
    cleanup(&ctx);
    return res;
}
