#include "cli.h"
#include <ctype.h>
#include <signal.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  // POSIX getopt, isatty, _exit

#define CLI_PROMPT       "sfm> "
#define CLI_LINE_MAX     1025  // 1023 command chars + '\n' + '\0'
#define CLI_MAX_TOKENS   8     // command name + arguments
#define SECRET_SLOTS_MAX 16

typedef struct {
    volatile void *ptr;
    size_t len;
} SecretSlot;

static SecretSlot secret_slots[SECRET_SLOTS_MAX] = {};
static volatile sig_atomic_t has_saved_termios = 0;
static struct termios saved_termios_copy = {};

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

/* ================= signal handling & secret registry ================= */

static const int ignored_signals[] = {SIGINT, SIGQUIT, SIGTSTP};
static const int term_signals[] = {SIGTERM, SIGHUP};

static void block_term_signals(sigset_t *old_mask) {
    sigset_t mask;
    sigemptyset(&mask);
    for (size_t i = 0; i < sizeof term_signals / sizeof term_signals[0]; i++) {
        (void)sigaddset(&mask, term_signals[i]);
    }
    (void)sigprocmask(SIG_BLOCK, &mask, old_mask);
}

static void restore_signal_mask(const sigset_t *old_mask) {
    (void)sigprocmask(SIG_SETMASK, old_mask, nullptr);
}

/**
 * @brief Async-signal-safe termination handler: zeroes every registered
 *        secret buffer in RAM, restores terminal ECHO if active, and exits.
 */
static void handle_termination_signal(int sig) {
    for (size_t i = 0; i < SECRET_SLOTS_MAX; i++) {
        volatile unsigned char *p = (volatile unsigned char *)secret_slots[i].ptr;
        const size_t n = secret_slots[i].len;
        if (p != nullptr && n > 0) {
            for (size_t j = 0; j < n; j++) {
                p[j] = 0U;
            }
        }
    }

    if (has_saved_termios != 0) {
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_copy);
    }

    _exit(128 + sig);
}

void cli_register_secret(volatile void *ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;

    sigset_t old_mask;
    block_term_signals(&old_mask);

    for (size_t i = 0; i < SECRET_SLOTS_MAX; i++) {
        if (secret_slots[i].ptr == nullptr) {
            secret_slots[i].len = len;
            atomic_signal_fence(memory_order_seq_cst);
            secret_slots[i].ptr = ptr;
            break;
        }
    }

    restore_signal_mask(&old_mask);
}

void cli_unregister_secret(volatile void *ptr) {
    if (ptr == nullptr) return;

    sigset_t old_mask;
    block_term_signals(&old_mask);

    for (size_t i = 0; i < SECRET_SLOTS_MAX; i++) {
        if (secret_slots[i].ptr == ptr) {
            secret_slots[i].ptr = nullptr;
            atomic_signal_fence(memory_order_seq_cst);
            secret_slots[i].len = 0;
            break;
        }
    }

    restore_signal_mask(&old_mask);
}

void cli_register_termios(const struct termios *saved) {
    if (saved == nullptr) return;

    sigset_t old_mask;
    block_term_signals(&old_mask);

    saved_termios_copy = *saved;
    atomic_signal_fence(memory_order_seq_cst);
    has_saved_termios = 1;

    restore_signal_mask(&old_mask);
}

void cli_unregister_termios(void) {
    sigset_t old_mask;
    block_term_signals(&old_mask);

    has_saved_termios = 0;

    restore_signal_mask(&old_mask);
}

bool cli_ignore_signals(void) {
    struct sigaction ignore = {};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);

    for (size_t i = 0; i < sizeof ignored_signals / sizeof ignored_signals[0]; i++) {
        if (sigaction(ignored_signals[i], &ignore, nullptr) != 0) return false;
    }

    struct sigaction terminate = {};
    terminate.sa_handler = handle_termination_signal;
    sigfillset(&terminate.sa_mask);

    for (size_t i = 0; i < sizeof term_signals / sizeof term_signals[0]; i++) {
        if (sigaction(term_signals[i], &terminate, nullptr) != 0) return false;
    }

    return true;
}

/* ================= interactive shell ================= */

typedef struct {
    const char *name;
    CommandHandler handler;
    int min_args;
    int max_args;
    const char *usage;
    const char *description;
} CliCommand;

static const CliCommand command_table[] = {
    {"list", cmd_list, 0, 0, "list", "List the encrypted files in the vault"},
    {"encrypt", cmd_encrypt, 1, 1, "encrypt <absolute_path>", "Encrypt a file into the vault"},
    {"decrypt", cmd_decrypt, 2, 2, "decrypt <file_in_vault> <absolute_destination_directory>", "Decrypt a file from the vault to a directory"},
    {"secure_delete", cmd_secure_delete, 1, 1, "secure_delete <vault_file_or_absolute_path>", "Securely delete one of your files (vault or not)"},
};

#define COMMAND_COUNT (sizeof command_table / sizeof command_table[0])
#define TOKENIZE_TOO_MANY (-1)
#define TOKENIZE_OPEN_QUOTE (-2)

static int tokenize(char *line, char *tokens[], int max) {
    int count = 0;
    char *p = line;

    while (*p != '\0') {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        if (count == max) return TOKENIZE_TOO_MANY;

        char *out = p;
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

static const CliCommand *find_command(const char *name) {
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(command_table[i].name, name) == 0) return &command_table[i];
    }
    return nullptr;
}

static void print_shell_help(void) {
    printf("Commands:\n");
    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        printf("  %-26s %s\n", command_table[i].name, command_table[i].description);
    }
    printf("  %-26s %s\n", "help", "Show this help");
    printf("  %-26s %s\n", "exit", "Leave sfm");
    printf("Tip: use double quotes around paths that contain spaces.\n");
}

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
    if (count == 0) return true;

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

static CliStatus shell_loop(const CommandContext *ctx) {
    printf("Type 'help' for the list of commands, 'exit' to quit.\n");

    char line[CLI_LINE_MAX];
    cli_register_secret(line, sizeof line);

    while (true) {
        (void)fputs(CLI_PROMPT, stdout);
        (void)fflush(stdout);

        if (fgets(line, sizeof line, stdin) == nullptr) {
            sodium_memzero(line, sizeof line);
            if (ferror(stdin)) {
                cli_unregister_secret(line);
                (void)fprintf(stderr, "Error reading input.\n");
                return CLI_ERROR;
            }
            if (!isatty(STDIN_FILENO)) {
                cli_unregister_secret(line);
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
            continue;
        }

        const bool keep_running = execute_line(ctx, line);
        sodium_memzero(line, sizeof line);
        if (!keep_running) {
            cli_unregister_secret(line);
            return CLI_EXIT_SUCCESS;
        }
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