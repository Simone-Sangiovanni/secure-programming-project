#ifndef SFM_COMMANDS_H
#define SFM_COMMANDS_H

#include "../config/config.h"

/**
 * @file commands.h
 * @brief Interactive shell commands: list, encrypt, decrypt, secure_delete.
 *
 * Commands receive all dependencies via CommandContext (no global state).
 */

/** Dependencies passed to every command handler. */
typedef struct {
    const SfmConfig *cfg;       /**< Loaded configuration (vault path, KDF, etc.). */
    const unsigned char *key;   /**< File-encryption key from auth (AUTH_KEY_BYTES bytes). */
} CommandContext;

/** Result codes returned by every command. */
typedef enum {
    CMD_OK = 0,                 /**< Command succeeded. */
    CMD_ERR_NOT_IMPLEMENTED,    /**< Command exists but is not implemented yet. */
    CMD_ERR_FAILED              /**< Command failed (error details already printed). */
} CommandStatus;

/** Shared signature for all commands (argc/argv exclude the command name). */
typedef CommandStatus (*CommandHandler)(const CommandContext *ctx, int argc, char *argv[]);

/** Lists encrypted (.sfm) files in the vault. Takes no arguments. */
[[nodiscard]] CommandStatus cmd_list(const CommandContext *ctx, int argc, char *argv[]);

/**
 * Encrypts <absolute_path> into "<vault>/<basename>.sfm" using ctx->key
 * and securely deletes the plaintext source file. Never overwrites existing files.
 */
[[nodiscard]] CommandStatus cmd_encrypt(const CommandContext *ctx, int argc, char *argv[]);

/**
 * Decrypts <file_in_vault> into <absolute_destination_directory> without ".sfm".
 * Keeps the vault copy and never overwrites existing output files.
 */
[[nodiscard]] CommandStatus cmd_decrypt(const CommandContext *ctx, int argc, char *argv[]);

/**
 * Securely deletes <vault_file | absolute_path>.
 * Plain names (no '/') target "<vault>/<name>.sfm"; absolute paths target any
 * user-owned regular file (symlinks, directories, and other users' files refused).
 */
[[nodiscard]] CommandStatus cmd_secure_delete(const CommandContext *ctx, int argc, char *argv[]);

/** Returns a human-readable message for a CommandStatus (never NULL). */
[[nodiscard]] const char *command_strerror(CommandStatus status);

#endif
