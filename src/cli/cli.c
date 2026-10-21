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