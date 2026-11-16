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

/**
 * @brief Disables core dumps so secrets in RAM are not written to disk on crash.
 */
static void disable_core_dumps(void) {
    const struct rlimit zero = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &zero);
}

/**
 * @brief Checks whether the vault directory already contains any ".sfm" files.
 *
 * Used during first-run detection: if the config file was deleted or blanked
 * while encrypted files already exist in the vault, creating a new master
 * password would generate a new salt and make existing files unrecoverable.
 *
 * @param vault_path Path to the vault directory.
 * @return true if at least one ".sfm" file is present, false otherwise.
 */
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
 * @brief Creates the folders and files sfm needs on the first run, then
 *        loads the configuration.
 *
 * The configuration file is created by init_setup() if it does not exist, so
 * a failure to load it here is a real error (corrupt or unreadable file).
 * Continuing with defaults would risk overwriting a valid configuration.
 *
 * @param cfg Output configuration.
 * @return true if @p cfg is ready to use, false (after printing why) if not.
 */
static bool prepare_config(SfmConfig *cfg) {
    SfmPaths paths;
    const InitStatus is = init_setup(&paths);
    if (is != INIT_OK) {
        (void)fprintf(stderr, "Initialization failed: %s\n", init_strerror(is));
        return false;
    }
    const ConfigStatus cs = load_config(paths.config_file, cfg);
    if (cs != CONFIG_OK) {
        (void)fprintf(stderr, "Initialization failed: configuration file is missing or invalid.\n");
        return false;
    }
    return true;
}

/**
 * @brief Creates the master password on the first run, logs in otherwise.
 *
 * @param cfg Loaded configuration (updated and saved on first run).
 * @param key Receives the file-encryption key on success.
 * @return AUTH_OK on success, otherwise the reason it failed.
 */
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
        const AuthStatus setup_status = auth_setup_master_password(cfg, key);  // also saves the config file
        log_audit_event(cfg,
                        LOG_EVENT_MASTER_SETUP,
                        (setup_status == AUTH_OK) ? LOG_OUTCOME_SUCCESS : LOG_OUTCOME_FAILURE,
                        nullptr);
        return setup_status;
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
        case CLI_OK:           break;  // proceed to run sfm
    }

    // Ignore Ctrl-C, Ctrl-\, and Ctrl-Z before password entry so an interrupt
    // cannot leave the terminal with ECHO disabled.
    if (!cli_ignore_signals()) {
        (void)fprintf(stderr, "Cannot protect the process from terminal signals.\n");
        return EXIT_FAILURE;
    }

    printf("Starting %s...\n", program_name);

    SfmConfig cfg;
    if (!prepare_config(&cfg)) return EXIT_FAILURE;

    unsigned char key[AUTH_KEY_BYTES] = {};
    int exit_code = EXIT_FAILURE;

    const AuthStatus as = authenticate(&cfg, key);
    if (as == AUTH_OK) {
        printf("Authenticated.\n");

        // Interactive shell: runs until the user types `exit`.
        const CommandContext ctx = {.cfg = &cfg, .key = key};
        if (cli_run(&ctx) == CLI_EXIT_SUCCESS) exit_code = EXIT_SUCCESS;
    } else {
        (void)fprintf(stderr, "Authentication failed: %s\n", auth_strerror(as));
    }

    sodium_memzero(key, sizeof key);  // wipe the key on every path
    return exit_code;
}
