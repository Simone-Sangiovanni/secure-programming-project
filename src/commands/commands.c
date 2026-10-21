#include "commands.h"

#include <stdio.h>

/*
 * Stubs: each one prints what it received so the shell can be tested, then
 * reports CMD_ERR_NOT_IMPLEMENTED. Replace the body of each function with
 * the real implementation (and return CMD_OK / CMD_ERR_FAILED).
 */

/** Stub for `list`. */
CommandStatus cmd_list([[maybe_unused]] const CommandContext *ctx,
                       [[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
    // TODO: no vault yet.
    return CMD_ERR_NOT_IMPLEMENTED;
}

/** Stub for `encrypt <absolute_path>`; argv[0] is the path. */
CommandStatus cmd_encrypt([[maybe_unused]] const CommandContext *ctx,
                          [[maybe_unused]] int argc, char *argv[]) {
    printf("[stub] encrypt '%s'\n", argv[0]);
    // TODO(validate): validate the path (checkpoint 3).
    // TODO: read file -> encrypt with ctx->key -> write output file.
    return CMD_ERR_NOT_IMPLEMENTED;
}

/** Stub for `decrypt <absolute_path>`; argv[0] is the path. */
CommandStatus cmd_decrypt([[maybe_unused]] const CommandContext *ctx,
                          [[maybe_unused]] int argc, char *argv[]) {
    printf("[stub] decrypt '%s'\n", argv[0]);
    // TODO: read file -> decrypt with ctx->key -> write output file.
    return CMD_ERR_NOT_IMPLEMENTED;
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
        case CMD_ERR_FAILED:          return "command failed";
    }
    return "unknown error";
}