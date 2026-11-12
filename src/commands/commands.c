#include "commands.h"

#include <stdio.h>
#include <string.h>

#include "../filecrypt/filecrypt.h"
#include "../validate/validate.h"

#define ENCRYPTED_EXT     ".sfm"
#define ENCRYPTED_EXT_LEN (sizeof ENCRYPTED_EXT - 1)

/* ---------- helpers (private to this file) ---------- */

/**
 * @brief Prints why an encrypt/decrypt operation failed.
 *
 * Helper function to centralize error reporting. It differentiates between
 * IO errors (file not found, permissions) and cryptographic errors (wrong key,
 * corrupted data).
 *
 * @param cmd_name "encrypt" or "decrypt".
 * @param in_path  Input path (blamed for input-side errors).
 * @param out_path Output path (blamed for output-side errors).
 * @param result   The failed result containing the specific error codes.
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

/* ---------- commands ---------- */

/**
 * @brief Implementation of the `list` command (stub).
 *
 * @param ctx  Command context.
 * @param argc Number of arguments.
 * @param argv Array of arguments.
 * @return CMD_ERR_NOT_IMPLEMENTED.
 */
CommandStatus cmd_list([[maybe_unused]] const CommandContext *ctx,
                       [[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
    // TODO: no vault yet.
    return CMD_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief Implementation of the `encrypt` command.
 *
 * Steps:
 * 1. Validate that the input path is a clean absolute path.
 * 2. Extract the base file name from the input path.
 * 3. Construct the output path inside the user's isolated vault, appending ".sfm".
 * 4. Stream the file through the cipher using filecrypt_encrypt().
 *
 * Security checks included: path validation (directory traversal prevention),
 * and strict buffer bounds checking when constructing the output path.
 *
 * @param ctx  Command context (provides configuration and the encryption key).
 * @param argc Number of arguments (guaranteed to be 1 by the CLI).
 * @param argv Array of arguments (argv[0] is the absolute path to the file).
 * @return CMD_OK on success, or CMD_ERR_FAILED on any error.
 */
CommandStatus cmd_encrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    // Security check: ensure required context and key are present to prevent null-pointer dereferences
    if (ctx == nullptr || ctx->key == nullptr || ctx->cfg == nullptr) return CMD_ERR_FAILED;

    const char *in_path = argv[0];
    
    // 1. Validate input path (prevents directory traversal and ensures absolute path)
    const ValidateStatus vs = validate_absolute_path(in_path);
    if (vs != VALIDATE_OK) {
        (void)fprintf(stderr, "encrypt: %s\n", validate_strerror(vs));
        return CMD_ERR_FAILED;
    }

    // 2. Extract the file name to place it inside the vault
    const char *slash = strrchr(in_path, '/');
    const char *basename = (slash != nullptr) ? slash + 1 : in_path;

    // 3. Construct the output path inside the vault securely
    char out_path[VALIDATE_PATH_MAX];
    
    // Buffer overflow prevention via snprintf bounds checking
    const int n = snprintf(out_path, sizeof out_path, "%s/%s%s", ctx->cfg->vault_path, basename, ENCRYPTED_EXT);
    if (n < 0 || (size_t)n >= sizeof out_path) {
        (void)fprintf(stderr, "encrypt: the output file name would be too long\n");
        return CMD_ERR_FAILED;
    }

    // 4. Stream the file through the cipher
    const FileCryptResult result = filecrypt_encrypt(ctx->key, in_path, out_path);
    if (!filecrypt_ok(result)) {
        print_failure("encrypt", in_path, out_path, result);
        return CMD_ERR_FAILED;
    }

    printf("Encrypted: '%s' -> '%s'\n", in_path, out_path);
    return CMD_OK;
}

/**
 * @brief Implementation of the `decrypt` command.
 *
 * Steps:
 * 1. Validate that the destination is an absolute path.
 * 2. Validate that the requested vault file contains no directory separators
 *    (preventing path traversal attacks out of the vault) and ends with ".sfm".
 * 3. Construct the input path (vault_dir + vault_file) and the output path
 *    (dest_dir + vault_file without ".sfm").
 * 4. Stream the file through the cipher using filecrypt_decrypt().
 *
 * Memory buffers and paths are strictly bounds-checked to prevent buffer overflows
 * and unauthorized file access.
 *
 * @param ctx  Command context (provides configuration and the encryption key).
 * @param argc Number of arguments (guaranteed to be 2 by the CLI).
 * @param argv Array of arguments (argv[0] is vault file, argv[1] is destination dir).
 * @return CMD_OK on success, or CMD_ERR_FAILED on any error.
 */
CommandStatus cmd_decrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    // Security check: ensure required context and key are present
    if (ctx == nullptr || ctx->key == nullptr || ctx->cfg == nullptr) return CMD_ERR_FAILED;

    const char *vault_file = argv[0];
    const char *out_dir = argv[1];

    // 1. Validate absolute destination path to ensure predictable output locations
    if (out_dir == nullptr || out_dir[0] != '/') {
        (void)fprintf(stderr, "decrypt: destination must be an absolute path\n");
        return CMD_ERR_FAILED;
    }

    // 2. Security check: strictly prevent path traversal out of the vault by ensuring the vault file is just a filename
    if (strchr(vault_file, '/') != nullptr) {
        (void)fprintf(stderr, "decrypt: vault file name must not contain '/'\n");
        return CMD_ERR_FAILED;
    }

    // Ensure the file has the correct encrypted extension
    const size_t name_len = strlen(vault_file);
    if (name_len <= ENCRYPTED_EXT_LEN || strcmp(vault_file + name_len - ENCRYPTED_EXT_LEN, ENCRYPTED_EXT) != 0) {
        (void)fprintf(stderr, "decrypt: only files ending in '" ENCRYPTED_EXT "' can be decrypted\n");
        return CMD_ERR_FAILED;
    }

    // 3. Construct the input path securely (inside the vault)
    char in_path[VALIDATE_PATH_MAX];
    
    // Buffer overflow prevention via snprintf
    int n = snprintf(in_path, sizeof in_path, "%s/%s", ctx->cfg->vault_path, vault_file);
    if (n < 0 || (size_t)n >= sizeof in_path) {
        (void)fprintf(stderr, "decrypt: the input file name would be too long\n");
        return CMD_ERR_FAILED;
    }

    // 4. Construct the output path securely
    char out_path[VALIDATE_PATH_MAX];
    
    // Strip trailing slashes from the output directory path for clean concatenation
    size_t dir_len = strlen(out_dir);
    while (dir_len > 1 && out_dir[dir_len - 1] == '/') dir_len--;

    // Buffer overflow prevention for output path
    n = snprintf(out_path, sizeof out_path, "%.*s/%.*s", (int)dir_len, out_dir, (int)(name_len - ENCRYPTED_EXT_LEN), vault_file);
    if (n < 0 || (size_t)n >= sizeof out_path) {
        (void)fprintf(stderr, "decrypt: the output file name would be too long\n");
        return CMD_ERR_FAILED;
    }

    // 5. Stream the file through the cipher
    const FileCryptResult result = filecrypt_decrypt(ctx->key, in_path, out_path);
    if (!filecrypt_ok(result)) {
        print_failure("decrypt", in_path, out_path, result);
        return CMD_ERR_FAILED;
    }

    printf("Decrypted: '%s' -> '%s'\n", in_path, out_path);
    return CMD_OK;
}

/**
 * @brief Implementation of the `secure_delete` command (stub).
 *
 * @param ctx  Command context.
 * @param argc Number of arguments.
 * @param argv Array of arguments.
 * @return CMD_ERR_NOT_IMPLEMENTED.
 */
CommandStatus cmd_secure_delete([[maybe_unused]] const CommandContext *ctx,
                                [[maybe_unused]] int argc, char *argv[]) {
    printf("[stub] secure_delete '%s'\n", argv[0]);
    // TODO: no vault yet.
    return CMD_ERR_NOT_IMPLEMENTED;
}

/**
 * @brief Returns a human-readable string for a CommandStatus.
 */
const char *command_strerror(CommandStatus status) {
    switch (status) {
        case CMD_OK:                  return "ok";
        case CMD_ERR_NOT_IMPLEMENTED: return "not implemented yet";
        case CMD_ERR_FAILED:          return "failed";
    }
    return "unknown error";
}
