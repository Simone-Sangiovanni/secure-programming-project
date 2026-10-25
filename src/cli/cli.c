#include <stddef.h>
#define _POSIX_C_SOURCE 200809L  // for getopt / optind / optopt with -std=c23

#include "cli.h"

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // POSIX getopt

#define CLI_PROMPT      "sfm> "
#define CLI_LINE_MAX    1024 // longest accepted input line (including '\0')
#define CLI_MAX_TOKENS  8 // command name + arguments



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

    opterr = 0;
    optind = 1;

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
    const char *name; // what the user types
    CommandHandler handler; //function in commands.c
    int min_args; // accepted number of arguments (after the name)
    int max_args;
    const char *usage; // show on wrong usage and in 'help'
    const char *description; // show in 'help'
} CliCommand;

static const CliCommand command_table[] = {
    {"list", cmd_list, 0, 0, "list", "List the encrypted files in the vault"},
    {"encrypt", cmd_encrypt, 1, 1, "encrypt <absolute_path>", "Encrypt a file"},
    {"decrypt", cmd_decrypt, 1, 1, "decrypt <absolute_path>", "Decrypt a file"},
    {"secure_delete", cmd_secure_delete, 1, 1, "secure_delete <file_name>", "Securely delete a file from the vault"},
};

#define COMMAND_COUNT (sizeof command_table / sizeof command_table[0])

// return the value of tokenize() on error
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

    // itearte to the end of the line
    while (*p != '\0') {
        // skip any leading spaces, tabs or new lines
        while(isspace((unsigned char)*p)) p++;
        if (*p == '\0') break; // end of the line
        if (count == max) return TOKENIZE_TOO_MANY; // too many words

        char *out = p; // write position (neve ahead of the read position)
        tokens[count++] = out;

        bool in_quotes = false; // keeps track of whether the parser is currently inside a quoted string
        // spaces found inside quotes are threated as regular characters
        while (*p != '\0' && (in_quotes || !isspace((unsigned char)*p))) {
            if (*p == '"') {
                in_quotes = !in_quotes;
                p++; // skip over the quote character
            } else {
                *out++ = *p++; // copy the character from p to out and advances both pointer
            }
        }
        // the loop finishes with open quotes -> error
        if (in_quotes) return TOKENIZE_OPEN_QUOTE;

        char *next = (*p != '\0') ? p+1 : p;
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
        if (strcmp(command_table[i].name, name) == 0) return  &command_table[i];
    }
    return nullptr;
}

/**
 * @brief Prints the list of shell commands.
 */
static void print_shell_help(void) {
    printf("Commands:\n");
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        /**
            -: left align
            26: fixed minimum field width of 26 characters
            s: string
        */
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
    // split the line in tokens
    char *tokens[CLI_MAX_TOKENS];
    const int count = tokenize(line, tokens, CLI_MAX_TOKENS);

    // catches common errors
    if (count == TOKENIZE_TOO_MANY) {
        (void)fprintf(stderr, "Too many arguments.\n");
        return true;
    }
    if (count == TOKENIZE_OPEN_QUOTE) {
        (void)fprintf(stderr, "Missing closing quote.\n");
        return true;
    }
    if (count == 0) return true; // empty line

    // process main commands
    const char *name = tokens[0];
    if (strcmp(name, "exit") == 0) return false; // the only way to leave the shell
    if (strcmp(name, "help") == 0) {
        print_shell_help();
        return true;
    }

    // find commands and if they do not exists throw an error
    const CliCommand *cmd = find_command(name);
    if (cmd == nullptr) {
        (void)fprintf(stderr, "Unkown command '%s'. Type 'help' for the list of commands.\n", name);
        return true;
    }

    // counts the arguments
    const int nargs = count - 1;
    if (nargs < cmd->min_args || nargs > cmd->max_args) {
        (void)fprintf(stderr, "Usage: %s.\n", cmd->usage);
        return true;
    }

    // if everything is valid calls the command's specific handler function
    const CommandStatus st = cmd->handler(ctx, nargs, &tokens[1]);
    if (st != CMD_OK) {
        (void)fprintf(stderr, "%s: %s.\n", cmd->name, command_strerror(st));
    }
    return true;
}

// Signals ignored while the shell runs: Ctrl-C, Ctrl-\ and Ctrl-Z
static const int ignored_signals[] = {SIGINT, SIGQUIT, SIGTSTP};

/**
 * @brief Makes the process ignore the keyboard signals that would stop it.
 *
 *  - SIGINT  (Ctrl-C):  would terminate the program.
 *  - SIGQUIT (Ctrl-\):  would terminate it and may write a core dump, which
 *                       could contain the encryption key.
 *  - SIGTSTP (Ctrl-Z):  would suspend it, leaving the key in memory of a
 *                       stopped process.
 *
 * The signals stay ignored until the process exits (so that main can still
 * wipe the key without being interrupted). SIGTERM, SIGHUP and SIGKILL are
 * deliberately NOT blocked: the system and the user must still be able to
 * stop the program from outside (closing the terminal, `kill`).
 *
 * @return true on success, false if a signal could not be ignored.
 */
static bool ignore_keyboard_signals(void) {
    struct sigaction ignore = {}; // initialize signal action
    ignore.sa_handler = SIG_IGN; // tells the OS to ignore the incoming signals
    sigemptyset(&ignore.sa_mask); // clears any additional signals that would be blocked while handling this setup

    // itherate through the signals
    for (size_t i = 0; i < sizeof ignored_signals / sizeof ignored_signals[0]; i++) {
        // Applies the ignore behavior to each signal
        if (sigaction(ignored_signals[i], &ignore, nullptr) != 0) return false; 
    }
    return true;
}

/**
 * @brief The read-parse-execute loop. Returns only when the user types `exit`
 *        or when the input is lost for good.
 *
 * Ctrl-D is ignored. At the start of a line it only produces an "end of
 * input" condition, which is cleared, and a hint is printed. In the middle
 * of a line it has no effect at all (the C library keeps reading until the
 * newline).
 *
 * @return CLI_EXIT_SUCCESS after `exit`; CLI_ERROR if reading failed or stdin
 *         is no longer a terminal (e.g. the terminal was closed), because
 *         without input the loop could never end.
 */
static CliStatus shell_loop(const CommandContext *ctx) {
    printf("Type 'help' for the list of commands, 'exit' to quit.\n");
    
    char line[CLI_LINE_MAX];
    while (true) {
        // print the '>' prompt sign and immediately flush the output stream to make it appear in the screen right away
        (void)fputs(CLI_PROMPT, stdout);
        (void)fflush(stdout);

        // reads the line up to CLI_LINE_MAX characters. if nullptr it means there has been an error
        if (fgets(line, sizeof line, stdin) == nullptr) {
            if (ferror(stdin)) {
                (void)fprintf(stderr, "Error reading input.\n");
                return CLI_ERROR;
            }
            // End of input. On a live terminal this is just Ctrl-D: ignore it.
            // If stdin is not a terminal any more, no input will ever come
            // again, so looping would spin forever: stop instead.
            if (!isatty(STDIN_FILENO)) {
                (void)fprintf(stderr, "\nInput closed.\n");
                return CLI_ERROR;
            }
            // Resets the error flags and the EOF indicator for the given file stream
            clearerr(stdin);
            printf("\nUse 'exit' to quit.\n");
            continue;
        }

        // find '\n' and replace it with '\0'
        const size_t len = strcspn(line, "\n");
        if (line[len] == '\n') {
            line[len] = '\0';
        } else if (len == sizeof line - 1) {
            // buffer full and no newline: prevent buffer overflow capturing the remaining characters and re-ask for the input
            int c;
            while ((c = getchar()) != '\n' && c != EOF ) { /* discard the rest*/ }
            (void)fprintf(stderr, "Line too long (max %d characters)", CLI_LINE_MAX -1);
            continue;
        } else {
            continue; // partial line cut short by end of input; ignore it
        }

        // passes the command line string to the execution logic
        if (!execute_line(ctx, line)) return CLI_EXIT_SUCCESS;
    }
}

CliStatus cli_run(const CommandContext *ctx) {
    if (ctx == nullptr) return CLI_ERROR;

    if (!ignore_keyboard_signals()) {
        (void) fprintf(stderr, "Cannot protect the shell from interruption.\n");
        return CLI_ERROR;
    }
    return shell_loop(ctx);
}