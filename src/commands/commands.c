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

static bool valid_ctx(const CommandContext *ctx, bool need_key) {
    return ctx != nullptr && ctx->cfg != nullptr && (!need_key || ctx->key != nullptr);
}

static bool has_sfm_ext(const char *name) {
    const size_t len = strlen(name);
    return len > ENCRYPTED_EXT_LEN && strcmp(name + len - ENCRYPTED_EXT_LEN, ENCRYPTED_EXT) == 0;
}

static bool build_path(char out[static VALIDATE_PATH_MAX],
                       const char *dir, const char *name, size_t name_len, const char *ext) {
    size_t dir_len = strlen(dir);
    while (dir_len > 1 && dir[dir_len - 1] == '/') dir_len--;
    const int n = snprintf(out, VALIDATE_PATH_MAX, "%.*s/%.*s%s",
                           (int)dir_len, dir, (int)name_len, name, ext);
    return n >= 0 && (size_t)n < VALIDATE_PATH_MAX;
}

static CommandStatus fail_cmd(const SfmConfig *cfg, LogEvent event,
                              const char *target, const char *cmd, const char *msg) {
    (void)fprintf(stderr, "%s: %s\n", cmd, msg);
    log_audit_event(cfg, event, LOG_OUTCOME_FAILURE, target);
    return CMD_ERR_FAILED;
}

static CommandStatus fail_crypt(const SfmConfig *cfg, LogEvent event, const char *target,
                                const char *cmd, const char *in_path, const char *out_path,
                                FileCryptResult res) {
    const bool on_out = (res.io != FILEIO_OK && res.io_on_output);
    const char *err = (res.io != FILEIO_OK) ? fileio_strerror(res.io) : cipher_strerror(res.cipher);
    (void)fprintf(stderr, "%s: '%s': %s\n", cmd, on_out ? out_path : in_path, err);
    log_audit_event(cfg, event, LOG_OUTCOME_FAILURE, target);
    return CMD_ERR_FAILED;
}

CommandStatus cmd_list(const CommandContext *ctx,
                       [[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
    if (!valid_ctx(ctx, false)) return CMD_ERR_FAILED;

    DIR *dir = opendir(ctx->cfg->vault_path);
    if (dir == nullptr) {
        return fail_cmd(ctx->cfg, LOG_EVENT_LIST_FILES, nullptr, "list", "cannot open vault directory");
    }

    size_t count = 0;
    for (const struct dirent *ent; (ent = readdir(dir)) != nullptr;) {
        if (has_sfm_ext(ent->d_name)) {
            for (const char *p = ent->d_name; *p != '\0'; p++) {
                const unsigned char c = (unsigned char)*p;
                (void)putchar(iscntrl(c) ? '?' : c);
            }
            (void)putchar('\n');
            count++;
        }
    }
    (void)closedir(dir);

    if (count == 0) printf("(vault is empty)\n");
    log_audit_event(ctx->cfg, LOG_EVENT_LIST_FILES, LOG_OUTCOME_SUCCESS, nullptr);
    return CMD_OK;
}

CommandStatus cmd_encrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    if (!valid_ctx(ctx, true)) return CMD_ERR_FAILED;
    const char *req_path = argv[0];

    char in_path[VALIDATE_PATH_MAX];
    const ValidateStatus vs = validate_file_path(req_path, in_path);
    if (vs != VALIDATE_OK) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, req_path, "encrypt", validate_strerror(vs));
    }

    const char *slash = strrchr(in_path, '/');
    const char *base = (slash != nullptr) ? slash + 1 : in_path;

    char out_path[VALIDATE_PATH_MAX];
    if (!build_path(out_path, ctx->cfg->vault_path, base, strlen(base), ENCRYPTED_EXT)) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, base,
                        "encrypt", "the output file name would be too long");
    }

    const FileCryptResult res = filecrypt_encrypt(ctx->key, in_path, out_path);
    if (!filecrypt_ok(res)) {
        return fail_crypt(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, base, "encrypt", in_path, out_path, res);
    }

    printf("Encrypted: '%s' -> '%s'\n", in_path, out_path);
    log_audit_event(ctx->cfg, LOG_EVENT_FILE_ENCRYPT, LOG_OUTCOME_SUCCESS, base);

    const FileIoStatus del = fileio_secure_delete(in_path);
    if (del != FILEIO_OK) {
        (void)fprintf(stderr,
                      "encrypt: warning: encrypted file saved, but could not securely delete source '%s': %s\n",
                      in_path, fileio_strerror(del));
    }
    log_audit_event(ctx->cfg, LOG_EVENT_FILE_DELETE,
                    del == FILEIO_OK ? LOG_OUTCOME_SUCCESS : LOG_OUTCOME_FAILURE, base);
    return CMD_OK;
}

CommandStatus cmd_decrypt(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    if (!valid_ctx(ctx, true)) return CMD_ERR_FAILED;
    const char *vault_file = argv[0];
    const char *out_dir = argv[1];

    char resolved_dir[VALIDATE_PATH_MAX];
    const ValidateStatus vs = validate_directory_path(out_dir, resolved_dir);
    if (vs != VALIDATE_OK) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DECRYPT, vault_file, "decrypt", validate_strerror(vs));
    }
    if (strchr(vault_file, '/') != nullptr) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DECRYPT, vault_file,
                        "decrypt", "vault file name must not contain '/'");
    }
    if (!has_sfm_ext(vault_file)) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DECRYPT, vault_file,
                        "decrypt", "only files ending in '" ENCRYPTED_EXT "' can be decrypted");
    }

    char in_path[VALIDATE_PATH_MAX], out_path[VALIDATE_PATH_MAX];
    if (!build_path(in_path, ctx->cfg->vault_path, vault_file, strlen(vault_file), "")) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DECRYPT, vault_file,
                        "decrypt", "the input file name would be too long");
    }
    if (!build_path(out_path, resolved_dir, vault_file, strlen(vault_file) - ENCRYPTED_EXT_LEN, "")) {
        return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DECRYPT, vault_file,
                        "decrypt", "the output file name would be too long");
    }

    const FileCryptResult res = filecrypt_decrypt(ctx->key, in_path, out_path);
    if (!filecrypt_ok(res)) {
        return fail_crypt(ctx->cfg, LOG_EVENT_FILE_DECRYPT, vault_file, "decrypt", in_path, out_path, res);
    }

    printf("Decrypted: '%s' -> '%s'\n", in_path, out_path);
    log_audit_event(ctx->cfg, LOG_EVENT_FILE_DECRYPT, LOG_OUTCOME_SUCCESS, vault_file);
    return CMD_OK;
}

CommandStatus cmd_secure_delete(const CommandContext *ctx, [[maybe_unused]] int argc, char *argv[]) {
    if (!valid_ctx(ctx, false)) return CMD_ERR_FAILED;
    const char *arg = argv[0];
    char target_path[VALIDATE_PATH_MAX];

    if (strchr(arg, '/') == nullptr) {
        if (!has_sfm_ext(arg)) {
            return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DELETE, arg, "secure_delete",
                            "a vault file name must end in '" ENCRYPTED_EXT
                            "' (use an absolute path to delete other files)");
        }
        if (!build_path(target_path, ctx->cfg->vault_path, arg, strlen(arg), "")) {
            return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DELETE, arg, "secure_delete", "the file path is too long");
        }
    } else {
        const ValidateStatus vs = validate_file_path(arg, target_path);
        if (vs != VALIDATE_OK) {
            return fail_cmd(ctx->cfg, LOG_EVENT_FILE_DELETE, arg, "secure_delete", validate_strerror(vs));
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