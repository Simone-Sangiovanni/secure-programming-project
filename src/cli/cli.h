#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include <termios.h>
#include "../commands/commands.h"

constexpr char program_version[] = "1.0.0";
constexpr char program_name[] = "sfm (Secure File Manager)";

// Status returned by the CLI parser
typedef enum : unsigned char {
    CLI_OK = 0,         // Arguments parsed successfully, proceed with program execution
    CLI_EXIT_SUCCESS,   // Processed a flag like -h or -v; exit program normally
    CLI_ERROR           // Invalid arguments encountered; exit with error
} CliStatus;

[[nodiscard]] CliStatus cli_parse(int argc, char *argv[]);

/**
 * Installs signal handling for the process:
 * - Ignores interactive terminal signals (SIGINT, SIGQUIT, SIGTSTP) so the
 *   process cannot be suspended with secrets in RAM or interrupted while
 *   terminal ECHO is disabled.
 * - Installs an async-signal-safe termination handler on SIGTERM and SIGHUP
 *   that zeroes all registered secret buffers in RAM and restores terminal
 *   attributes before exiting.
 *
 * @return true on success, false if a signal handler could not be installed.
 */
[[nodiscard]] bool cli_ignore_signals(void);

/**
 * Registers a sensitive memory buffer so the termination signal handler
 * (SIGTERM/SIGHUP) zeroes it in an async-signal-safe manner before exit.
 */
void cli_register_secret(volatile void *ptr, size_t len);

/**
 * Unregisters a sensitive memory buffer after it has been wiped and released.
 */
void cli_unregister_secret(volatile void *ptr);

/**
 * Registers saved terminal settings during non-echo password input so a
 * termination signal restores terminal ECHO before process exit.
 */
void cli_register_termios(const struct termios *saved);

/**
 * Clears the registered terminal settings once normal restoration completes.
 */
void cli_unregister_termios(void);

[[nodiscard]] CliStatus cli_run(const CommandContext *ctx);
void cli_print_help(void);
void cli_print_version(void);

#endif