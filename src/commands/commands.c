#include "commands.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

#include "../filecrypt/filecrypt.h"
#include "../fileio/fileio.h"
#include "../log/log.h"
#include "../validate/validate.h"

#define ENCRYPTED_EXT     ".sfm"
#define ENCRYPTED_EXT_LEN (sizeof ENCRYPTED_EXT - 1)

/* ---------- helpers (private to this file) ---------- */

static void print_failure(const char *cmd_name, const char *in_path, const char *out_path,
                          FileCryptResult result) {
    if (result.io != FILEIO_OK) {
        (void)fprintf(stderr, "%s: '%s': %s\n", cmd_name,
                      result.io_on_output ? out_path : in_path, fileio_strerror(result.io));
    } else {
        (void)fprintf(stderr, "%s: '%s': %s\n", cmd_name, in_path, cipher_strerror(result.cipher));
    }
}

static bool has_encrypted_extension(const char *name) {
    const size_t len = strlen(name);
    return len > ENCRYPTED_EXT_LEN &&
           strcmp(name + len - ENCRYPTED_EXT_LEN, ENCRYPTED_EXT) == 0;
}

static void print_sanitized_name(const char *name) {
    for (size_t i = 0; name[i] != '\0'; i++) {
        const unsigned char c = (unsigned char)name[i];
        (void)putchar(iscntrl(c) ? '?' : (int)c);
    }
    (void)putchar('\n');
}

/* ---------- commands ---------- */

CommandStatus cmd_list(const CommandContext *ctx,
                       [[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
    if (ctx == nullptr || ctx->cfg == nullptr) return CMD_ERR_FAILED;

    DIR *dir = opendir(ctx->cfg->vault_path);
    if (dir == nullptr) {
        (void)fprintf(stderr, "list: cannot open vault directory\n");
        log_audit_event(ctx->cfg, LOG_EVENT_LIST_FILES, LOG_OUTCOME_FAILURE, nullptr);
        return CMD_ERR_FAILED;
    }

    size_t count = 0;
    const struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (has_encrypted_extension(entry->d_name)) {
            print_sanitized_name(entry->d_name);
            count++;
        }
    }
    (void)closedir(dir);

    if (count == 0) {
        printf("(vault is empty)\n");
    }

    log_audit_event(ctx->cfg, LOG_EVENT_LIST_FILES, LOG_OUTCOME_SUCCESS, nullptr);
    return CMD_OK;
}

CommandStatus cmd_encrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    if (ctx == nullptr || ctx->key == nullptr || ctx->cfg == nullptr) return CMD_ERR_FAILED;
    const char *requested_path = argv[0];

    // 1. Validate the path text and canonicalize its parent directory.
    //    The file itself is not resolved: it is opened with O_NOFOLLOW later.
    char in_path[VALIDATE_PATH_MAX];
    const ValidateStatus vs = validate_file_path(requested_path, in_path);
    if (vs != VALIDATE_OK) {
        (void)fprintf(stderr, "encrypt: %s\n", validate_strerror(vs));
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, LOG_OUTCOME_FAILURE, requested_path);
        return CMD_ERR_FAILED;
    }

    // 2. Extract the base file name to place it inside the vault
    const char *slash = strrchr(in_path, '/');
    const char *basename = (slash != nullptr) ? slash + 1 : in_path;

    // 3. Construct the output path inside the vault securely
    char out_path[VALIDATE_PATH_MAX];
    const int n = snprintf(out_path, sizeof out_path, "%s/%s%s",
                           ctx->cfg->vault_path, basename, ENCRYPTED_EXT);
    if (n < 0 || (size_t)n >= sizeof out_path) {
        (void)fprintf(stderr, "encrypt: the output file name would be too long\n");
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, LOG_OUTCOME_FAILURE, basename);
        return CMD_ERR_FAILED;
    }

    // 4. Stream the file through the cipher
    const FileCryptResult result = filecrypt_encrypt(ctx->key, in_path, out_path);
    if (!filecrypt_ok(result)) {
        print_failure("encrypt", in_path, out_path, result);
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, LOG_OUTCOME_FAILURE, basename);
        return CMD_ERR_FAILED;
    }

    printf("Encrypted: '%s' -> '%s'\n", in_path, out_path);
    log_audit_event(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, LOG_OUTCOME_SUCCESS, basename);

    // 5. Securely remove the original plaintext source file
    const FileIoStatus del_status = fileio_secure_delete(in_path);
    if (del_status != FILEIO_OK) {
        (void)fprintf(stderr,
                      "encrypt: warning: encrypted file saved, but could not securely delete source '%s': %s\n",
                      in_path, fileio_strerror(del_status));
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_FAILURE, basename);
    } else {
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_SUCCESS, basename);
    }

    return CMD_OK;
}

CommandStatus cmd_decrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    if (ctx == nullptr || ctx->key == nullptr || ctx->cfg == nullptr) return CMD_ERR_FAILED;
    const char *vault_file = argv[0];
    const char *out_dir = argv[1];

    // 1. Validate and canonicalize destination directory path
    char resolved_dir[VALIDATE_PATH_MAX];
    const ValidateStatus vs = validate_directory_path(out_dir, resolved_dir);
    if (vs != VALIDATE_OK) {
        (void)fprintf(stderr, "decrypt: %s\n", validate_strerror(vs));
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_FAILURE, vault_file);
        return CMD_ERR_FAILED;
    }

    // 2. Ensure the vault file is a plain filename (no '/') ending in ".sfm"
    if (strchr(vault_file, '/') != nullptr) {
        (void)fprintf(stderr, "decrypt: vault file name must not contain '/'\n");
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_FAILURE, vault_file);
        return CMD_ERR_FAILED;
    }
    if (!has_encrypted_extension(vault_file)) {
        (void)fprintf(stderr, "decrypt: only files ending in '" ENCRYPTED_EXT "' can be decrypted\n");
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_FAILURE, vault_file);
        return CMD_ERR_FAILED;
    }

    // 3. Construct the input path inside the vault
    char in_path[VALIDATE_PATH_MAX];
    int n = snprintf(in_path, sizeof in_path, "%s/%s", ctx->cfg->vault_path, vault_file);
    if (n < 0 || (size_t)n >= sizeof in_path) {
        (void)fprintf(stderr, "decrypt: the input file name would be too long\n");
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_FAILURE, vault_file);
        return CMD_ERR_FAILED;
    }

    // 4. Construct the output path inside the canonical destination directory
    const size_t name_len = strlen(vault_file);
    size_t dir_len = strlen(resolved_dir);
    while (dir_len > 1 && resolved_dir[dir_len - 1] == '/') dir_len--;

    char out_path[VALIDATE_PATH_MAX];
    n = snprintf(out_path, sizeof out_path, "%.*s/%.*s",
                 (int)dir_len, resolved_dir, (int)(name_len - ENCRYPTED_EXT_LEN), vault_file);
    if (n < 0 || (size_t)n >= sizeof out_path) {
        (void)fprintf(stderr, "decrypt: the output file name would be too long\n");
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_FAILURE, vault_file);
        return CMD_ERR_FAILED;
    }

    // 5. Stream the file through the cipher
    const FileCryptResult result = filecrypt_decrypt(ctx->key, in_path, out_path);
    if (!filecrypt_ok(result)) {
        print_failure("decrypt", in_path, out_path, result);
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_FAILURE, vault_file);
        return CMD_ERR_FAILED;
    }

    printf("Decrypted: '%s' -> '%s'\n", in_path, out_path);
    log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_SUCCESS, vault_file);
    return CMD_OK;
}

CommandStatus cmd_secure_delete(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    if (ctx == nullptr || ctx->cfg == nullptr) return CMD_ERR_FAILED;
    const char *arg = argv[0];
    char target_path[VALIDATE_PATH_MAX];

    if (strchr(arg, '/') == nullptr) {
        // A plain name: a file of the vault.
        if (!has_encrypted_extension(arg)) {
            (void)fprintf(stderr,
                          "secure_delete: a vault file name must end in '" ENCRYPTED_EXT
                          "' (use an absolute path to delete other files)\n");
            log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_FAILURE, arg);
            return CMD_ERR_FAILED;
        }
        const int n = snprintf(target_path, sizeof target_path, "%s/%s", ctx->cfg->vault_path, arg);
        if (n < 0 || (size_t)n >= sizeof target_path) {
            (void)fprintf(stderr, "secure_delete: the file path is too long\n");
            log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_FAILURE, arg);
            return CMD_ERR_FAILED;
        }
    } else {
        // A path: any file of the user, inside or outside the vault. The directory part is
        // canonicalized; the file itself is opened with O_NOFOLLOW and its owner is verified.
        const ValidateStatus vs = validate_file_path(arg, target_path);
        if (vs != VALIDATE_OK) {
            (void)fprintf(stderr, "secure_delete: %s\n", validate_strerror(vs));
            log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_FAILURE, arg);
            return CMD_ERR_FAILED;
        }
    }

    const FileIoStatus st = fileio_secure_delete(target_path);
    if (st != FILEIO_OK) {
        (void)fprintf(stderr, "secure_delete: '%s': %s\n", arg, fileio_strerror(st));
        log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_FAILURE, arg);
        return CMD_ERR_FAILED;
    }

    printf("Deleted: '%s'\n", target_path);
    log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE, LOG_OUTCOME_SUCCESS, arg);
    return CMD_OK;
}

const char *command_strerror(CommandStatus status) {
    switch (status) {
        case CMD_OK:                  return "ok";
        case CMD_ERR_NOT_IMPLEMENTED: return "not implemented yet";
        case CMD_ERR_FAILED:          return "failed";
    }
    return "unknown error";
}
