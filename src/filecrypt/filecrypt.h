#ifndef SFM_FILECRYPT_H
#define SFM_FILECRYPT_H

#include "../cipher/cipher.h"
#include "../fileio/fileio.h"

typedef struct {
    FileIoStatus io;
    CipherStatus cipher;
    bool io_on_output;
} FileCryptResult;

[[nodiscard]] bool filecrypt_ok(FileCryptResult result);
[[nodiscard]] FileCryptResult filecrypt_encrypt(const unsigned char kek[CIPHER_KEY_BYTES],
                                                const char *in_path, const char *out_path);
[[nodiscard]] FileCryptResult filecrypt_decrypt(const unsigned char kek[CIPHER_KEY_BYTES],
                                                const char *in_path, const char *out_path);

#endif