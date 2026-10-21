#ifndef CLI_H 
#define CLI_H

#include "../commands/commands.h"

constexpr char program_version[] = "1.0.0";
constexpr char program_name[] ="sfm (Secure File Manager)";

// status returned by the CLI parser
typedef enum : unsigned char {
    CLI_OK = 0,         // Arguments parsed successfully, proceed with program execution
    CLI_EXIT_SUCCESS,   // Processed a flag like -h or -v; exit program normally
    CLI_ERROR           // Invalid arguments encountered; exit with error
} CliStatus;

/**
 * Parses command-line arguments for sfm.
 *
 * Mark function return as [[nodiscard]] so callers cannot ignore the status.
 *
 * @param argc  Argument count from main()
 * @param argv  Argument vector from main()
 * @return CliStatus indicating execution outcome 
 */
[[nodiscard]] CliStatus cli_parse(int argc, char *argv[]);

/**
 * Runs the interactive shell ("sfm> " prompt).
 *
 * The ONLY way to leave the shell is the command `exit`. Ctrl-C, Ctrl-\ and
 * Ctrl-Z are ignored (and stay ignored until the process ends), and Ctrl-D
 * does nothing but print a hint.
 *
 * Each line is split into a command and its arguments, the argument count
 * is checked, and the matching function from commands.h is called.
 * Mistakes by the user (unknown command, wrong arguments, a failing
 * command) print a message and the shell keeps running.
 *
 * @param ctx  Context handed to every command. Must not be NULL.
 * @return CLI_EXIT_SUCCESS after `exit`. CLI_ERROR if @p ctx is NULL, the
 *         signals could not be ignored, or the input was lost (reading
 *         failed, or stdin stopped being a terminal).
 */
[[nodiscard]] CliStatus cli_run(const CommandContext *ctx);

/**
 * Prints the help usage message.
 */
void cli_print_help(void);

/**
 * Prints the program version.
 */
void cli_print_version(void);

#endif