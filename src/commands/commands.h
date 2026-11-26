#ifndef SFM_COMMANDS_H
#define SFM_COMMANDS_H

#include "../config/config.h"

typedef struct {
    const SfmConfig *cfg;
    const unsigned char *key;
} CommandContext;

typedef enum {
    CMD_OK = 0,
    CMD_ERR_NOT_IMPLEMENTED,
    CMD_ERR_FAILED
} CommandStatus;

typedef CommandStatus (*CommandHandler)(const CommandContext *ctx, int argc, char *argv[]);

[[nodiscard]] CommandStatus cmd_list(const CommandContext *ctx, int argc, char *argv[]);
[[nodiscard]] CommandStatus cmd_encrypt(const CommandContext *ctx, int argc, char *argv[]);
[[nodiscard]] CommandStatus cmd_decrypt(const CommandContext *ctx, int argc, char *argv[]);
[[nodiscard]] CommandStatus cmd_secure_delete(const CommandContext *ctx, int argc, char *argv[]);
[[nodiscard]] const char *command_strerror(CommandStatus status);

#endif