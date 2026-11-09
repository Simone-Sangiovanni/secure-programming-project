#include "commands.h"

#include <stdio.h>
#include <string.h>

#include "../filecrypt/filecrypt.h"
#include "../validate/validate.h"

#define ENCRYPTED_EXT     ".sfm"
#define ENCRYPTED_EXT_LEN (sizeof ENCRYPTED_EXT - 1)



/* ---------- helpers (private to this file) ---------- */



/**
 * @brief Works out the output path of an encrypt or decrypt operation.
 *
 * Encrypting appends ".sfm"; decrypting requires the ".sfm" suffix and
 * removes it.
 *
 * @param out        Buffer receiving the output path.
 * @param out_size   Size of @p out.
 * @param path       Input path (already validated).
 * @param encrypting true for encrypt, false for decrypt.
 * @return NULL on success, otherwise a message explaining the problem.
 */
static const char *build_output_path(char *out, size_t out_size, const char *path, bool encrypting) {
    const size_t len = strlen(path);

    if (encrypting) {
        const int n = snprintf(out, out_size, "%s%s", path, ENCRYPTED_EXT);
        if (n < 0 || (size_t)n >= out_size) return "the output file name would be too long";
        return nullptr;
    }

    if (len <= ENCRYPTED_EXT_LEN || strcmp(path + len - ENCRYPTED_EXT_LEN, ENCRYPTED_EXT) != 0) {
        return "only files ending in '" ENCRYPTED_EXT "' can be decrypted";
    }
    const int n = snprintf(out, out_size, "%.*s", (int)(len - ENCRYPTED_EXT_LEN), path);
    if (n < 0 || (size_t)n >= out_size) return "the output file name would be too long";
    return nullptr;
}

/**
 * @brief Prints why an encrypt/decrypt operation failed.
 *
 * @param cmd_name "encrypt" or "decrypt".
 * @param in_path  Input path (blamed for input-side errors).
 * @param out_path Output path (blamed for output-side errors).
 * @param result   The failed result.
 */
static void print_failure(const char *cmd_name, const char *in_path, const char *out_path,
                          FileCryptResult result) {
    if (result.io != FILEIO_OK) {
        (void)fprintf(stderr, "%s: '%s': %s\n", cmd_name,
                      result.io_on_output ? out_path : in_path, fileio_strerror(result.io));
    } else {
        (void)fprintf(stderr, "%s: '%s': %s\n", cmd_name, in_path, cipher_strerror(result.cipher));
    }
}

/**
 * @brief Shared implementation of encrypt and decrypt for a single file.
 *
 * Steps: validate path -> derive output path -> stream the file through the
 * cipher (see filecrypt). Errors are printed here, so callers only get
 * CMD_ERR_FAILED.
 *
 * @param ctx        Command context (needs ctx->key).
 * @param cmd_name   "encrypt" or "decrypt", used in messages.
 * @param path       Path typed by the user.
 * @param encrypting true to encrypt, false to decrypt.
 * @return CMD_OK or CMD_ERR_FAILED.
 */
static CommandStatus process_file(const CommandContext *ctx, const char *cmd_name,
                                  const char *path, bool encrypting) {
    if (ctx == nullptr || ctx->key == nullptr || path == nullptr) return CMD_ERR_FAILED;

    const ValidateStatus vs = validate_absolute_path(path);
    if (vs != VALIDATE_OK) {
        (void)fprintf(stderr, "%s: %s\n", cmd_name, validate_strerror(vs));
        return CMD_ERR_FAILED;
    }

    char out_path[VALIDATE_PATH_MAX];
    const char *path_error = build_output_path(out_path, sizeof out_path, path, encrypting);
    if (path_error != nullptr) {
        (void)fprintf(stderr, "%s: %s\n", cmd_name, path_error);
        return CMD_ERR_FAILED;
    }

    const FileCryptResult result = encrypting ? filecrypt_encrypt(ctx->key, path, out_path)
                                              : filecrypt_decrypt(ctx->key, path, out_path);
    if (!filecrypt_ok(result)) {
        print_failure(cmd_name, path, out_path, result);
        return CMD_ERR_FAILED;
    }

    printf("%s: '%s' -> '%s'\n", encrypting ? "Encrypted" : "Decrypted", path, out_path);
    return CMD_OK;
}



/* ---------- commands ---------- */



/** Stub for `list`. */
CommandStatus cmd_list([[maybe_unused]] const CommandContext *ctx,
                       [[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
    // TODO: no vault yet.
    return CMD_ERR_NOT_IMPLEMENTED;
}

/** `encrypt <absolute_path>`: argv[0] is the path (the cli guarantees argc == 1). */
CommandStatus cmd_encrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    return process_file(ctx, "encrypt", argv[0], true);
}

/** `decrypt <absolute_path>`: argv[0] is the path (the cli guarantees argc == 1). */
CommandStatus cmd_decrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    return process_file(ctx, "decrypt", argv[0], false);
}

/** Stub for `secure_delete <file_name>`; argv[0] is the vault file name. */
CommandStatus cmd_secure_delete([[maybe_unused]] const CommandContext *ctx,
                                [[maybe_unused]] int argc, char *argv[]) {
    printf("[stub] secure_delete '%s'\n", argv[0]);
    // TODO: no vault yet.
    return CMD_ERR_NOT_IMPLEMENTED;
}

/** Implementation of command_strerror(). */
const char *command_strerror(CommandStatus status) {
    switch (status) {
        case CMD_OK:                  return "ok";
        case CMD_ERR_NOT_IMPLEMENTED: return "not implemented yet";
        case CMD_ERR_FAILED:          return "failed";
    }
    return "unknown error";
}