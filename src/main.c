#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "auth/auth.h"
#include "cli/cli.h"
#include "config/config.h"

#ifndef DEFAULT_CONFIG_PATH
#define DEFAULT_CONFIG_PATH "/home/echo-00/Desktop/projects/secure-programming-project/config.json"  // TODO: move to ~/.config/sfm/config.json
#endif

int main(int argc, char *argv[]) {
    const CliStatus status = cli_parse(argc, argv);

    switch (status) {
        case CLI_EXIT_SUCCESS: return EXIT_SUCCESS;
        case CLI_ERROR: return EXIT_FAILURE;
        case CLI_OK: break;  // proceed to run sfm
    }

    printf("Starting %s...\n", program_name);

    // Load the config file; if it does not exist yet, start from defaults.
    SfmConfig cfg;
    const ConfigStatus cs = load_config(DEFAULT_CONFIG_PATH, &cfg);

    if (cs == CONFIG_ERR_NOT_FOUND) {
        if (config_set_defaults(&cfg, DEFAULT_CONFIG_PATH) != CONFIG_OK) {
            (void)fprintf(stderr, "Cannot create default configuration.\n");
            return EXIT_FAILURE;
        }
    } else if (cs != CONFIG_OK) {
        (void)fprintf(stderr, "Cannot load config (error %d)\n", (int)cs);
        return EXIT_FAILURE;
    }

    // Authenticate: create the master password on first run, log in otherwise.
    // On success `key` holds the file-encryption key.
    unsigned char key[AUTH_KEY_BYTES] = {};
    AuthStatus as;

    if (config_is_first_run(&cfg)) {
        printf("No master password set. Let's create one.\n");
        as = auth_setup_master_password(&cfg, key);  // also saves the config file
    } else {
        as = auth_login(&cfg, key);
    }

    if (as != AUTH_OK) {
        (void)fprintf(stderr, "Authentication failed: %s\n", auth_strerror(as));
        return EXIT_FAILURE;
    }
    printf("Authenticated.\n");

    // TODO: run the command chosen on the command line (encrypt / decrypt ...)
    //       using `key`.

    // Interactive shell: runs until the user types `exit` (or presses Ctrl-D).
    const CommandContext ctx = {.cfg = &cfg, .key = &key};
    const CliStatus shell_status = cli_run(&ctx);

    sodium_memzero(key, sizeof key);  // wipe the key before exiting
    return EXIT_SUCCESS;
}