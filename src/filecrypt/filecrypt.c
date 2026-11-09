#include "filecrypt.h"

#include <stdlib.h>

#define ENC_CHUNK_MAX (CIPHER_CHUNK_SIZE + CIPHER_TAG_BYTES)  // bytes of one encrypted chunk

bool filecrypt_ok(FileCryptResult result) {
    return result.io == FILEIO_OK && result.cipher == CIPHER_OK;
}

FileCryptResult filecrypt_encrypt(const unsigned char key[CIPHER_KEY_BYTES],
                                  const char *in_path, const char *out_path) {
    FileCryptResult res = {FILEIO_OK, CIPHER_OK, false};
    if (key == nullptr || in_path == nullptr || out_path == nullptr) {
        res.cipher = CIPHER_ERR_ARGS;
        return res;
    }

    FileReader *in = nullptr;
    FileWriter *out = nullptr;
    CipherStream *stream = nullptr;
    unsigned char *plain = nullptr;
    unsigned char *enc = nullptr;
    unsigned char header[CIPHER_HEADER_BYTES];
    uint64_t size = 0;

    FileIoStatus fs = fileio_reader_open(in_path, &in, &size);
    if (fs != FILEIO_OK) { res.io = fs; goto cleanup; }

    // The encrypted file is larger than the input: check that IT fits too.
    if (cipher_encrypted_size(size) > FILEIO_MAX_SIZE) {
        res.io = FILEIO_ERR_TOO_BIG;
        res.io_on_output = true;
        goto cleanup;
    }

    plain = malloc(CIPHER_CHUNK_SIZE);
    enc = malloc(ENC_CHUNK_MAX);
    if (plain == nullptr || enc == nullptr) { res.io = FILEIO_ERR_ALLOC; goto cleanup; }

    CipherStatus cs = cipher_encrypt_begin(key, &stream, header);
    if (cs != CIPHER_OK) { res.cipher = cs; goto cleanup; }

    fs = fileio_writer_create(out_path, &out);
    if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; goto cleanup; }

    fs = fileio_writer_write(out, header, sizeof header);
    if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; goto cleanup; }

    uint64_t remaining = size;
    bool last;
    do {
        const size_t want = (remaining < CIPHER_CHUNK_SIZE) ? (size_t)remaining : CIPHER_CHUNK_SIZE;

        size_t got = 0;
        fs = fileio_reader_read(in, plain, want, &got);
        if (fs != FILEIO_OK) { res.io = fs; goto cleanup; }
        if (got != want) { res.io = FILEIO_ERR_READ; goto cleanup; }  // file shrank while reading

        remaining -= want;
        last = (remaining == 0);  // an empty file is one empty "last" chunk

        size_t enc_len = 0;
        cs = cipher_encrypt_chunk(stream, plain, want, last, enc, &enc_len);
        if (cs != CIPHER_OK) { res.cipher = cs; goto cleanup; }

        fs = fileio_writer_write(out, enc, enc_len);
        if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; goto cleanup; }
    } while (!last);

    fs = fileio_writer_finish(out);  // frees `out` whether it succeeds or not
    out = nullptr;
    if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; }

cleanup:
    fileio_writer_abort(out);  // no-op if finished; otherwise removes the partial file
    cipher_stream_free(stream);
    cipher_free(plain, CIPHER_CHUNK_SIZE);  // wipes: it held plaintext
    cipher_free(enc, ENC_CHUNK_MAX);
    fileio_reader_close(in);
    return res;
}

FileCryptResult filecrypt_decrypt(const unsigned char key[CIPHER_KEY_BYTES],
                                  const char *in_path, const char *out_path) {
    FileCryptResult res = {FILEIO_OK, CIPHER_OK, false};
    if (key == nullptr || in_path == nullptr || out_path == nullptr) {
        res.cipher = CIPHER_ERR_ARGS;
        return res;
    }

    FileReader *in = nullptr;
    FileWriter *out = nullptr;
    CipherStream *stream = nullptr;
    unsigned char *plain = nullptr;
    unsigned char *enc = nullptr;
    unsigned char header[CIPHER_HEADER_BYTES];
    uint64_t size = 0;
    size_t got = 0;

    FileIoStatus fs = fileio_reader_open(in_path, &in, &size);
    if (fs != FILEIO_OK) { res.io = fs; goto cleanup; }

    // Validate the header BEFORE creating any output file.
    fs = fileio_reader_read(in, header, sizeof header, &got);
    if (fs != FILEIO_OK) { res.io = fs; goto cleanup; }
    if (got != sizeof header) { res.cipher = CIPHER_ERR_FORMAT; goto cleanup; }

    CipherStatus cs = cipher_decrypt_begin(key, header, &stream);
    if (cs != CIPHER_OK) { res.cipher = cs; goto cleanup; }

    plain = malloc(CIPHER_CHUNK_SIZE);
    enc = malloc(ENC_CHUNK_MAX);
    if (plain == nullptr || enc == nullptr) { res.io = FILEIO_ERR_ALLOC; goto cleanup; }

    fs = fileio_writer_create(out_path, &out);
    if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; goto cleanup; }

    for (;;) {
        fs = fileio_reader_read(in, enc, ENC_CHUNK_MAX, &got);
        if (fs != FILEIO_OK) { res.io = fs; goto cleanup; }

        // got == 0 here means the file ended without a FINAL chunk (truncated):
        // cipher_decrypt_chunk reports that as an authentication failure.
        size_t plain_len = 0;
        bool last = false;
        cs = cipher_decrypt_chunk(stream, enc, got, plain, &plain_len, &last);
        if (cs != CIPHER_OK) { res.cipher = cs; goto cleanup; }

        // Every chunk except the last is full-size; anything else is not our format.
        if (!last && got != ENC_CHUNK_MAX) { res.cipher = CIPHER_ERR_AUTH; goto cleanup; }

        fs = fileio_writer_write(out, plain, plain_len);
        if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; goto cleanup; }

        if (last) {
            // Nothing may follow the FINAL chunk.
            unsigned char extra;
            size_t n = 0;
            fs = fileio_reader_read(in, &extra, 1, &n);
            if (fs != FILEIO_OK) { res.io = fs; goto cleanup; }
            if (n != 0) { res.cipher = CIPHER_ERR_AUTH; goto cleanup; }
            break;
        }
    }

    fs = fileio_writer_finish(out);  // frees `out` whether it succeeds or not
    out = nullptr;
    if (fs != FILEIO_OK) { res.io = fs; res.io_on_output = true; }

cleanup:
    fileio_writer_abort(out);  // no-op if finished; otherwise removes the partial plaintext
    cipher_stream_free(stream);
    cipher_free(plain, CIPHER_CHUNK_SIZE);
    cipher_free(enc, ENC_CHUNK_MAX);
    fileio_reader_close(in);
    return res;
}
