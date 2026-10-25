#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "auth/auth.h"
#include "cli/cli.h"
#include "commands/commands.h"
#include "config/config.h"

// Where the config file lives. Optionally override it at build time:
//   CMake: target_compile_definitions(sfm PRIVATE DEFAULT_CONFIG_PATH="/some/path/config.json")
//   shell: gcc -DDEFAULT_CONFIG_PATH='"/some/path/config.json"' ...
// (the quoting differs: the shell strips the outer single quotes, CMake does not need them)
#ifndef DEFAULT_CONFIG_PATH
#define DEFAULT_CONFIG_PATH "sfm_config.json"  // TODO: move to ~/.config/sfm/config.json
#endif

/**
 * @brief Loads the config file, or starts from defaults if it does not exist.
 *
 * A missing file is normal on the first run. A file that exists but cannot
 * be read or parsed is an error: continuing with defaults could lead to
 * overwriting a valid configuration.
 *
 * @param cfg Output configuration.
 * @return true if @p cfg is ready to use, false (after printing why) if not.
 */
static bool load_or_create_config(SfmConfig *cfg) {
    const ConfigStatus cs = load_config(DEFAULT_CONFIG_PATH, cfg);

    if (cs == CONFIG_OK) return true;

    if (cs == CONFIG_ERR_NOT_FOUND) {
        if (config_set_defaults(cfg, DEFAULT_CONFIG_PATH) == CONFIG_OK) return true;
        (void)fprintf(stderr, "Cannot create default configuration.\n");
        return false;
    }

    (void)fprintf(stderr, "Cannot load config '%s' (error %d)\n", DEFAULT_CONFIG_PATH, (int)cs);
    return false;
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
        printf("No master password set. Let's create one.\n");
        return auth_setup_master_password(cfg, key);  // also saves the config file
    }
    return auth_login(cfg, key);
}

int main(int argc, char *argv[]) {
    const CliStatus status = cli_parse(argc, argv);

    switch (status) {
        case CLI_EXIT_SUCCESS: return EXIT_SUCCESS;
        case CLI_ERROR:        return EXIT_FAILURE;
        case CLI_OK:           break;  // proceed to run sfm
    }

    printf("Starting %s...\n", program_name);

    SfmConfig cfg;
    if (!load_or_create_config(&cfg)) return EXIT_FAILURE;

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