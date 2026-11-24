#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include <termios.h>
#include "../commands/commands.h"

constexpr char program_version[] = "1.0.0";
constexpr char program_name[] = "sfm (Secure File Manager)";

typedef enum : unsigned char {
    CLI_OK = 0,         // Arguments parsed successfully; continue execution
    CLI_EXIT_SUCCESS,   // Handled informational flag (-h/-v) or 'exit' command
    CLI_ERROR           // Invalid arguments or unrecoverable I/O error
} CliStatus;

[[nodiscard]] CliStatus cli_parse(int argc, char *argv[]);
[[nodiscard]] CliStatus cli_run(const CommandContext *ctx);
void cli_print_help(void);
void cli_print_version(void);

/**
 * Ignores interactive signals (SIGINT, SIGQUIT, SIGTSTP) and installs an
 * async-signal-safe termination handler on SIGTERM and SIGHUP that wipes
 * registered secrets and restores terminal settings before exiting.
 */
[[nodiscard]] bool cli_ignore_signals(void);

/** Registers/unregisters sensitive RAM buffers to be wiped on SIGTERM/SIGHUP. */
void cli_register_secret(volatile void *ptr, size_t len);
void cli_unregister_secret(volatile void *ptr);

/** Registers/unregisters saved terminal attributes to restore ECHO on SIGTERM/SIGHUP. */
void cli_register_termios(const struct termios *saved);
void cli_unregister_termios(void);

#endif
