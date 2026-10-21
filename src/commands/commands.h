#ifndef SFM_COMMANDS_H
#define SFM_COMMANDS_H

#include "../config/config.h"

/**
 * @file commands.h
 * @brief The code that EXECUTES the shell commands (list, encrypt, ...).
 *
 * The cli module only parses what the user typed and calls one of these
 * functions. Everything a command needs comes through CommandContext, so
 * there is no global state.
 */

/** Everything a command needs to do its job. */
typedef struct {
    const SfmConfig *cfg;       /**< Loaded configuration (paths, kdf, ...). */
    const unsigned char *key;   /**< File-encryption key from auth (AUTH_KEY_BYTES bytes). */
} CommandContext;

/** Result codes returned by every command. */
typedef enum {
    CMD_OK = 0,                 /**< The command succeeded. */
    CMD_ERR_NOT_IMPLEMENTED,    /**< The command exists but is not written yet. */
    CMD_ERR_FAILED              /**< The command failed (details printed by the command). */
} CommandStatus;

/**
 * Signature shared by all commands. @p argc / @p argv are the arguments
 * AFTER the command name, and their count has already been checked by the
 * cli module (e.g. encrypt always receives exactly one argument).
 */
typedef CommandStatus (*CommandHandler)(const CommandContext *ctx, int argc, char *argv[]);

/** list: lists the encrypted files in the vault. Takes no arguments. */
[[nodiscard]] CommandStatus cmd_list(const CommandContext *ctx, int argc, char *argv[]);

/** encrypt <absolute_path>: encrypts the file at the given path. */
[[nodiscard]] CommandStatus cmd_encrypt(const CommandContext *ctx, int argc, char *argv[]);

/** decrypt <absolute_path>: decrypts the file at the given path. */
[[nodiscard]] CommandStatus cmd_decrypt(const CommandContext *ctx, int argc, char *argv[]);

/** secure_delete <file_name>: securely deletes a file from the vault. */
[[nodiscard]] CommandStatus cmd_secure_delete(const CommandContext *ctx, int argc, char *argv[]);

/** Returns a human-readable message for a CommandStatus (never NULL). */
[[nodiscard]] const char *command_strerror(CommandStatus status);

#endif