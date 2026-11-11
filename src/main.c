#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "auth/auth.h"
#include "cli/cli.h"
#include "commands/commands.h"
#include "config/config.h"
#include "init/init.h"

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
        (void)fprintf(stderr, "Cannot load config '%s' (error %d)\n", paths.config_file, (int)cs);
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