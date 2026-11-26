#include "cli.h"

#include <ctype.h>
#include <signal.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CLI_PROMPT "sfm> "

constexpr size_t CLI_LINE_MAX     = 1025;  // 1023 chars + '\n' + '\0'
constexpr int    CLI_MAX_TOKENS   = 8;
constexpr size_t SECRET_SLOTS_MAX = 16;

typedef struct {
    volatile void *ptr;
    size_t len;
} SecretSlot;

static SecretSlot secret_slots[SECRET_SLOTS_MAX] = {};
static volatile sig_atomic_t has_saved_termios = 0;
static struct termios saved_termios_copy = {};

void cli_print_help(void) {
    printf("Usage: %s [OPTION]\n\n"
           "Options:\n"
           "  -h    Show this help message and exit\n"
           "  -v    Show program version and exit\n",
           program_name);
}

void cli_print_version(void) {
    printf("%s version %s\n", program_name, program_version);
}

CliStatus cli_parse(int argc, char **argv) {
    opterr = 0;
    optind = 1;
    bool help = false, version = false;

    for (int opt; (opt = getopt(argc, argv, "hv")) != -1;) {
        switch (opt) {
            case 'h': help = true; break;
            case 'v': version = true; break;
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
    if (help)    { cli_print_help();    return CLI_EXIT_SUCCESS; }
    if (version) { cli_print_version(); return CLI_EXIT_SUCCESS; }
    return CLI_OK;
}

/* ---------- signal handling & secret registry ---------- */

static sigset_t block_term_signals(void) {
    sigset_t mask, old_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);
    return old_mask;
}

static void restore_signals(const sigset_t *old_mask) {
    sigprocmask(SIG_SETMASK, old_mask, nullptr);
}

/* Async-signal-safe cleanup: wipe registered secrets, restore ECHO, and exit. */
static void handle_termination_signal(int sig) {
    for (size_t i = 0; i < SECRET_SLOTS_MAX; i++) {
        volatile unsigned char *p = (volatile unsigned char *)secret_slots[i].ptr;
        const size_t n = secret_slots[i].len;
        if (p != nullptr) {
            for (size_t j = 0; j < n; j++) p[j] = 0U;
        }
    }
    if (has_saved_termios != 0) tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_copy);
    _exit(128 + sig);
}

void cli_register_secret(volatile void *ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;
    const sigset_t old = block_term_signals();
    for (size_t i = 0; i < SECRET_SLOTS_MAX; i++) {
        if (secret_slots[i].ptr == nullptr) {
            secret_slots[i].len = len;
            atomic_signal_fence(memory_order_seq_cst);
            secret_slots[i].ptr = ptr;
            break;
        }
    }
    restore_signals(&old);
}

void cli_unregister_secret(volatile void *ptr) {
    if (ptr == nullptr) return;
    const sigset_t old = block_term_signals();
    for (size_t i = 0; i < SECRET_SLOTS_MAX; i++) {
        if (secret_slots[i].ptr == ptr) {
            secret_slots[i].ptr = nullptr;
            atomic_signal_fence(memory_order_seq_cst);
            secret_slots[i].len = 0;
            break;
        }
    }
    restore_signals(&old);
}

void cli_register_termios(const struct termios *saved) {
    if (saved == nullptr) return;
    const sigset_t old = block_term_signals();
    saved_termios_copy = *saved;
    atomic_signal_fence(memory_order_seq_cst);
    has_saved_termios = 1;
    restore_signals(&old);
}

void cli_unregister_termios(void) {
    const sigset_t old = block_term_signals();
    has_saved_termios = 0;
    restore_signals(&old);
}

bool cli_ignore_signals(void) {
    struct sigaction ign = {.sa_handler = SIG_IGN};
    sigemptyset(&ign.sa_mask);
    if (sigaction(SIGINT, &ign, nullptr) != 0 ||
        sigaction(SIGQUIT, &ign, nullptr) != 0 ||
        sigaction(SIGTSTP, &ign, nullptr) != 0) {
        return false;
    }

    struct sigaction term = {.sa_handler = handle_termination_signal};
    sigfillset(&term.sa_mask);
    return sigaction(SIGTERM, &term, nullptr) == 0 && sigaction(SIGHUP, &term, nullptr) == 0;
}

/* ---------- interactive shell ---------- */

typedef struct {
    const char *name;
    CommandHandler handler;
    int expected_args;
    const char *usage;
    const char *description;
} CliCommand;

static const CliCommand commands[] = {
    {"list",          cmd_list,          0, "list",                                                   "List the encrypted files in the vault"},
    {"encrypt",       cmd_encrypt,       1, "encrypt <absolute_path>",                                "Encrypt a file into the vault"},
    {"decrypt",       cmd_decrypt,       2, "decrypt <file_in_vault> <absolute_destination_directory>", "Decrypt a file from the vault to a directory"},
    {"secure_delete", cmd_secure_delete, 1, "secure_delete <vault_file_or_absolute_path>",            "Securely delete one of your files (vault or not)"},
};

constexpr size_t COMMAND_COUNT = sizeof commands / sizeof commands[0];

static int tokenize(char *line, char *tokens[], int max) {
    int count = 0;
    for (char *p = line; *p != '\0';) {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        if (count == max) return -1;

        char *out = p;
        tokens[count++] = out;
        bool in_quotes = false;

        while (*p != '\0' && (in_quotes || !isspace((unsigned char)*p))) {
            if (*p == '"') { in_quotes = !in_quotes; p++; }
            else *out++ = *p++;
        }
        if (in_quotes) return -2;
        if (*p != '\0') p++;
        *out = '\0';
    }
    return count;
}

static bool execute_line(const CommandContext *ctx, char *line) {
    char *tokens[CLI_MAX_TOKENS];
    const int count = tokenize(line, tokens, CLI_MAX_TOKENS);
    if (count == -1) { (void)fprintf(stderr, "Too many arguments.\n"); return true; }
    if (count == -2) { (void)fprintf(stderr, "Missing closing quote.\n"); return true; }
    if (count == 0)  return true;

    const char *name = tokens[0];
    if (strcmp(name, "exit") == 0) return false;
    if (strcmp(name, "help") == 0) {
        printf("Commands:\n");
        for (size_t i = 0; i < COMMAND_COUNT; i++) {
            printf("  %-26s %s\n", commands[i].name, commands[i].description);
        }
        printf("  %-26s Show this help\n  %-26s Leave sfm\n"
               "Tip: use double quotes around paths that contain spaces.\n", "help", "exit");
        return true;
    }

    for (size_t i = 0; i < COMMAND_COUNT; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            if (count - 1 != commands[i].expected_args) {
                (void)fprintf(stderr, "Usage: %s.\n", commands[i].usage);
                return true;
            }
            const CommandStatus st = commands[i].handler(ctx, count - 1, &tokens[1]);
            if (st != CMD_OK) (void)fprintf(stderr, "%s: %s.\n", commands[i].name, command_strerror(st));
            return true;
        }
    }

    (void)fprintf(stderr, "Unknown command '%s'. Type 'help' for the list of commands.\n", name);
    return true;
}

CliStatus cli_run(const CommandContext *ctx) {
    if (ctx == nullptr) return CLI_ERROR;
    if (!cli_ignore_signals()) {
        (void)fprintf(stderr, "Cannot protect the shell from interruption.\n");
        return CLI_ERROR;
    }

    printf("Type 'help' for the list of commands, 'exit' to quit.\n");

    char line[CLI_LINE_MAX];
    cli_register_secret(line, sizeof line);
    CliStatus status = CLI_EXIT_SUCCESS;

    while (true) {
        (void)fputs(CLI_PROMPT, stdout);
        (void)fflush(stdout);

        if (fgets(line, sizeof line, stdin) == nullptr) {
            if (ferror(stdin)) {
                (void)fprintf(stderr, "Error reading input.\n");
                status = CLI_ERROR;
                break;
            }
            if (!isatty(STDIN_FILENO)) {
                (void)fprintf(stderr, "\nInput closed.\n");
                status = CLI_ERROR;
                break;
            }
            clearerr(stdin);
            printf("\nUse 'exit' to quit.\n");
            sodium_memzero(line, sizeof line);
            continue;
        }

        const size_t len = strcspn(line, "\n");
        if (line[len] == '\n') {
            line[len] = '\0';
            if (!execute_line(ctx, line)) break;
        } else if (len == sizeof line - 1) {
            for (int c; (c = getchar()) != '\n' && c != EOF;) {}
            (void)fprintf(stderr, "Line too long (max %zu characters).\n", CLI_LINE_MAX - 2);
        }
        sodium_memzero(line, sizeof line);
    }

    sodium_memzero(line, sizeof line);
    cli_unregister_secret(line);
    return status;
}