#ifndef CLI_H
#define CLI_H

#include <stddef.h>
#include <termios.h>
#include "../commands/commands.h"

constexpr char program_version[] = "1.0.0";
constexpr char program_name[] = "sfm (Secure File Manager)";

typedef enum : unsigned char {
    CLI_OK = 0,
    CLI_EXIT_SUCCESS,
    CLI_ERROR
} CliStatus;

[[nodiscard]] CliStatus cli_parse(int argc, char *argv[]);
[[nodiscard]] CliStatus cli_run(const CommandContext *ctx);
void cli_print_help(void);
void cli_print_version(void);

[[nodiscard]] bool cli_ignore_signals(void);
void cli_register_secret(volatile void *ptr, size_t len);
void cli_unregister_secret(volatile void *ptr);
void cli_register_termios(const struct termios *saved);
void cli_unregister_termios(void);

#endif