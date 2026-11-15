#include "cli.h"
#include <ctype.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  // POSIX getopt, isatty

#define CLI_PROMPT      "sfm> "
#define CLI_LINE_MAX    1025  // 1023 command chars + '\n' + '\0'
#define CLI_MAX_TOKENS  8     // command name + arguments

void cli_print_help(void) {
    printf("Usage: %s [OPTION]\n\n", program_name);
    printf("Options:\n");
    printf("  -h    Show this help message and exit\n");
    printf("  -v    Show program version and exit\n");
}

void cli_print_version(void) {
    printf("%s version %s\n", program_name, program_version);
}

CliStatus cli_parse(int argc, char **argv) {
    if (argc == 1) {
        return CLI_OK;
    }

    opterr = 0;  // disable getopt error messages
    optind = 1;  // tracks which element of argv will be processed next: skip argv[0]

    bool want_help = false;
    bool want_version = false;
    int opt;

    while ((opt = getopt(argc, argv, "hv")) != -1) {
        switch (opt) {
            case 'h': want_help = true; break;
            case 'v': want_version = true; break;
            default:
                (void)fprintf(stderr, "Error, invalid option '-%c'\n", optopt);
                cli_print_help();
                return CLI_ERROR;
        }
    }

    if (optind < argc) {
        (void)fprintf(stderr, "Error, unexpected argument '%s'\n", argv[optind]);
        cli_print_help();
        return CLI_ERROR;
    }

    if (want_help) {
        cli_print_help();
        return CLI_EXIT_SUCCESS;
    }

    if (want_version) {
        cli_print_version();
        return CLI_EXIT_SUCCESS;
    }

    return CLI_OK;
}

/* ================= interactive shell ================= */

/** One entry of the command table. To add a command, add a row here. */
typedef struct {
    const char *name;         // what the user types
    CommandHandler handler;   // function in commands.c
    int min_args;             // accepted number of arguments (after the name)
    int max_args;
    const char *usage;        // shown on wrong usage and in 'help'
    const char *description;  // shown in 'help'
} CliCommand;

static const CliCommand command_table[] = {
    {"list", cmd_list, 0, 0, "list", "List the encrypted files in the vault"},
    {"encrypt", cmd_encrypt, 1, 1, "encrypt <absolute_path>", "Encrypt a file into the vault"},
    {"decrypt", cmd_decrypt, 2, 2, "decrypt <file_in_vault> <absolute_destination_directory>", "Decrypt a file from the vault to a directory"},
    {"secure_delete", cmd_secure_delete, 1, 1, "secure_delete <file_name>", "Securely delete a file from the vault"},
};

#define COMMAND_COUNT (sizeof command_table / sizeof command_table[0])

// Return values of tokenize() on error
#define TOKENIZE_TOO_MANY (-1)
#define TOKENIZE_OPEN_QUOTE (-2)

/**
 * @brief Splits a line into words, in place.
 *
 * Words are separated by whitespace. Double quotes group text that contains
 * spaces (e.g. encrypt "/home/me/my file.txt"); the quotes themselves are
 * removed. @p line is modified: each word is NUL-terminated inside it.
 *
 * @param line     Line to split (modified).
 * @param tokens   Output array receiving a pointer to each word.
 * @param max      Capacity of @p tokens.
 * @return Number of words (0 for an empty line), TOKENIZE_TOO_MANY if there
 *         are more than @p max words, TOKENIZE_OPEN_QUOTE if a quote is
 *         never closed.
 */
static int tokenize(char *line, char *tokens[], int max) {
    int count = 0;
    char *p = line;

    while (*p != '\0') {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        if (count == max) return TOKENIZE_TOO_MANY;

        char *out = p;  // write position (never ahead of the read position)
        tokens[count++] = out;
        bool in_quotes = false;

        while (*p != '\0' && (in_quotes || !isspace((unsigned char)*p))) {
            if (*p == '"') {
                in_quotes = !in_quotes;
                p++;
            } else {
                *out++ = *p++;
            }
        }

        if (in_quotes) return TOKENIZE_OPEN_QUOTE;

        char *next = (*p != '\0') ? p + 1 : p;
        *out = '\0';
        p = next;
    }

    return count;
}

/**
 * @brief Returns the table entry for a command name, or NULL if unknown.
 */
static const CliCommand *find_command(const char *name) {
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(command_table[i].name, name) == 0) return &command_table[i];
    }
    return nullptr;
}

/**
 * @brief Prints the list of shell commands.
 */
static void print_shell_help(void) {
    printf("Commands:\n");
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        printf("  %-26s %s\n", command_table[i].name, command_table[i].description);
    }
    printf("  %-26s %s\n", "help", "Show this help");
    printf("  %-26s %s\n", "exit", "Leave sfm");
    printf("Tip: use double quotes around paths that contain spaces.\n");
}

/**
 * @brief Parses and runs one input line.
 *
 * @param ctx  Context passed to the command.
 * @param line Input line without the trailing newline (modified).
 * @return false if the user asked to leave the shell, true otherwise
 *         (including after any user mistake).
 */
static bool execute_line(const CommandContext *ctx, char *line) {
    char *tokens[CLI_MAX_TOKENS];
    const int count = tokenize(line, tokens, CLI_MAX_TOKENS);

    if (count == TOKENIZE_TOO_MANY) {
        (void)fprintf(stderr, "Too many arguments.\n");
        return true;
    }
    if (count == TOKENIZE_OPEN_QUOTE) {
        (void)fprintf(stderr, "Missing closing quote.\n");
        return true;
    }
    if (count == 0) return true;  // empty line

    const char *name = tokens[0];
    if (strcmp(name, "exit") == 0) return false;
    if (strcmp(name, "help") == 0) {
        print_shell_help();
        return true;
    }

    const CliCommand *cmd = find_command(name);
    if (cmd == nullptr) {
        (void)fprintf(stderr, "Unknown command '%s'. Type 'help' for the list of commands.\n", name);
        return true;
    }

    const int nargs = count - 1;
    if (nargs < cmd->min_args || nargs > cmd->max_args) {
        (void)fprintf(stderr, "Usage: %s.\n", cmd->usage);
        return true;
    }

    const CommandStatus st = cmd->handler(ctx, nargs, &tokens[1]);
    if (st != CMD_OK) {
        (void)fprintf(stderr, "%s: %s.\n", cmd->name, command_strerror(st));
    }

    return true;
}

// Signals ignored while the process runs: Ctrl-C, Ctrl-\ and Ctrl-Z
static const int ignored_signals[] = {SIGINT, SIGQUIT, SIGTSTP};

bool cli_ignore_signals(void) {
    struct sigaction ignore = {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);

    for (size_t i = 0; i < sizeof ignored_signals / sizeof ignored_signals[0]; i++) {
        if (sigaction(ignored_signals[i], &ignore, nullptr) != 0) return false;
    }
    return true;
}

/**
 * @brief The read-parse-execute loop. Returns only when the user types `exit`
 *        or when the input is lost for good.
 */
static CliStatus shell_loop(const CommandContext *ctx) {
    printf("Type 'help' for the list of commands, 'exit' to quit.\n");

    char line[CLI_LINE_MAX];
    while (true) {
        (void)fputs(CLI_PROMPT, stdout);
        (void)fflush(stdout);

        if (fgets(line, sizeof line, stdin) == nullptr) {
            sodium_memzero(line, sizeof line);
            if (ferror(stdin)) {
                (void)fprintf(stderr, "Error reading input.\n");
                return CLI_ERROR;
            }
            if (!isatty(STDIN_FILENO)) {
                (void)fprintf(stderr, "\nInput closed.\n");
                return CLI_ERROR;
            }
            clearerr(stdin);
            printf("\nUse 'exit' to quit.\n");
            continue;
        }

        const size_t len = strcspn(line, "\n");
        if (line[len] == '\n') {
            line[len] = '\0';
        } else if (len == sizeof line - 1) {
            int c;
            while ((c = getchar()) != '\n' && c != EOF) { /* discard the rest */ }
            sodium_memzero(line, sizeof line);
            (void)fprintf(stderr, "Line too long (max %d characters).\n", CLI_LINE_MAX - 2);
            continue;
        } else {
            sodium_memzero(line, sizeof line);
            continue;  // partial line cut short by end of input; ignore it
        }

        const bool keep_running = execute_line(ctx, line);
        sodium_memzero(line, sizeof line);
        if (!keep_running) return CLI_EXIT_SUCCESS;
    }
}

CliStatus cli_run(const CommandContext *ctx) {
    if (ctx == nullptr) return CLI_ERROR;
    if (!cli_ignore_signals()) {
        (void)fprintf(stderr, "Cannot protect the shell from interruption.\n");
        return CLI_ERROR;
    }
    return shell_loop(ctx);
}
