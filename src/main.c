#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sodium.h>

#include "auth/auth.h"
#include "cli/cli.h"
#include "commands/commands.h"
#include "config/config.h"
#include "init/init.h"
#include "log/log.h"

#define VAULT_FILE_EXT ".sfm"
#define VAULT_FILE_EXT_LEN (sizeof VAULT_FILE_EXT - 1)

static void disable_core_dumps(void) {
    const struct rlimit zero = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &zero);
}

static bool vault_has_encrypted_files(const char *vault_path) {
    if (vault_path == nullptr || vault_path[0] == '\0') return false;
    DIR *dir = opendir(vault_path);
    if (dir == nullptr) return false;

    bool found = false;
    const struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        const size_t len = strlen(entry->d_name);
        if (len > VAULT_FILE_EXT_LEN &&
            strcmp(entry->d_name + len - VAULT_FILE_EXT_LEN, VAULT_FILE_EXT) == 0) {
            found = true;
            break;
        }
    }
    (void)closedir(dir);
    return found;
}

/**
 * @brief Prepares sfm.config, parses it, and recreates/verifies the vault
 *        directory and log file at the paths specified in sfm.config.
 */
static bool prepare_config(SfmConfig *cfg) {
    SfmPaths paths;
    InitStatus is = init_prepare_config(&paths);
    if (is != INIT_OK) {
        (void)fprintf(stderr, "Initialization failed: %s\n", init_strerror(is));
        return false;
    }

    const ConfigStatus cs = load_config(paths.config_file, cfg);
    if (cs != CONFIG_OK) {
        (void)fprintf(stderr, "Initialization failed: configuration file is missing or invalid.\n");
        return false;
    }

    is = init_ensure_storage(cfg);
    if (is != INIT_OK) {
        (void)fprintf(stderr, "Initialization failed: %s\n", init_strerror(is));
        return false;
    }
    return true;
}

static AuthStatus authenticate(SfmConfig *cfg, unsigned char key[AUTH_KEY_BYTES]) {
    if (config_is_first_run(cfg)) {
        if (vault_has_encrypted_files(cfg->vault_path)) {
            (void)fprintf(stderr,
                          "Refusing first-run setup: encrypted files already exist in the vault.\n"
                          "Restore your original configuration file to access the existing vault.\n");
            log_audit_event(cfg, LOG_EVENT_MASTER_SETUP, LOG_OUTCOME_FAILURE, nullptr);
            return AUTH_ERR_CONFIG;
        }
        printf("No master password set. Let's create one.\n");
        printf("Password must be 8-64 characters long and include an uppercase letter, lowercase letter, number, and special character.\n");
        const AuthStatus setup_status = auth_setup_master_password(cfg, key);
        sodium_memzero(key, AUTH_KEY_BYTES);
        log_audit_event(cfg,
                        LOG_EVENT_MASTER_SETUP,
                        (setup_status == AUTH_OK) ? LOG_OUTCOME_SUCCESS : LOG_OUTCOME_FAILURE,
                        nullptr);
        if (setup_status != AUTH_OK) {
            return setup_status;
        }
        printf("Master password configured. Please log in to continue.\n");
    }

    const AuthStatus login_status = auth_login(cfg, key);
    log_audit_event(cfg,
                    LOG_EVENT_LOGIN,
                    (login_status == AUTH_OK) ? LOG_OUTCOME_SUCCESS : LOG_OUTCOME_FAILURE,
                    nullptr);
    return login_status;
}

int main(int argc, char *argv[]) {
    disable_core_dumps();

    const CliStatus status = cli_parse(argc, argv);
    switch (status) {
        case CLI_EXIT_SUCCESS: return EXIT_SUCCESS;
        case CLI_ERROR:        return EXIT_FAILURE;
        case CLI_OK:           break;
    }

    if (sodium_init() < 0) {
        (void)fprintf(stderr, "Initialization failed: cannot initialize cryptographic library.\n");
        return EXIT_FAILURE;
    }

    if (!cli_ignore_signals()) {
        (void)fprintf(stderr, "Cannot protect the process from terminal signals.\n");
        return EXIT_FAILURE;
    }

    printf("Starting %s...\n", program_name);

    SfmConfig cfg;
    if (!prepare_config(&cfg)) return EXIT_FAILURE;

    unsigned char key[AUTH_KEY_BYTES] = {};
    if (sodium_mlock(key, sizeof key) != 0) {
        (void)fprintf(stderr, "Initialization failed: cannot lock key memory.\n");
        return EXIT_FAILURE;
    }
    cli_register_secret(key, sizeof key);

    int exit_code = EXIT_FAILURE;

    const AuthStatus as = authenticate(&cfg, key);
    if (as == AUTH_OK) {
        printf("Authenticated.\n");

        const CommandContext ctx = {.cfg = &cfg, .key = key};
        if (cli_run(&ctx) == CLI_EXIT_SUCCESS) exit_code = EXIT_SUCCESS;
    } else {
        (void)fprintf(stderr, "Authentication failed: %s\n", auth_strerror(as));
    }

    cli_unregister_secret(key);
    sodium_memzero(key, sizeof key);
    (void)sodium_munlock(key, sizeof key);
    return exit_code;
}