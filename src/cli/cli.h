#ifndef CLI_H 
#define CLI_H

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
 * Prints the help usage message.
 */
void cli_print_help(void);

/**
 * Prints the program version.
 */
void cli_print_version(void);

#endif