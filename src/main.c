#include <stdio.h>
#include <stdlib.h>
#include "cli/cli.h"
#include "config/config.h"

#define DEFAULT_CONFIG_PATH "config.json"  // later: ~/.config/sfm/config.json

int main(int argc, char *argv[]) {
    const CliStatus status = cli_parse(argc, argv);

    switch (status) {
        case CLI_EXIT_SUCCESS: return EXIT_SUCCESS;
        case CLI_ERROR: return EXIT_FAILURE;
        case CLI_OK: break; // proceed to run sfm
    }

    printf("Starting %s...\n", program_name);

    SfmConfig cfg;
    const ConfigStatus cs = load_config(DEFAULT_CONFIG_PATH, &cfg);

    if (cs == CONFIG_ERR_NOT_FOUND) {
        if (config_set_defaults(&cfg, DEFAULT_CONFIG_PATH) != CONFIG_OK) return EXIT_FAILURE;
    } else if (cs != CONFIG_OK) {
        (void)fprintf(stderr, "Cannot load config (error %d)\n", (int)cs);
        return EXIT_FAILURE;
    }

    if (config_is_first_run(&cfg)) {
        // init(&cfg);   // set master password, save_config
    } else {
        // login(&cfg);  // verify master password
    }

    return EXIT_SUCCESS;
}

/*
#include <stdio.h>
#include <stdlib.h>
#include "init.h"

int main(void) {
    DirStatus status = setup_sfm_directory();

    switch (status) {
        case DIR_SUCCESS:
            printf("Success: Created 'sfm' directory inside '~/.config'.\n");
            return EXIT_SUCCESS;

        case DIR_ERR_HOME_NOT_FOUND:
            fprintf(stderr, "Error: Unable to determine home directory.\n");
            break;

        case DIR_ERR_PATH_TOO_LONG:
            fprintf(stderr, "Error: Home directory path exceeds maximum supported length.\n");
            break;

        case DIR_ERR_CONFIG_MISSING:
            fprintf(stderr, "Error: '~/.config' directory does not exist.\n");
            break;

        case DIR_ERR_CONFIG_NOT_DIR:
            fprintf(stderr, "Error: '~/.config' exists but is not a directory.\n");
            break;

        case DIR_ERR_CONFIG_ACCESS:
            fprintf(stderr, "Error: Lacking permissions to access '~/.config'.\n");
            break;

        case DIR_ERR_SFM_EXISTS:
            fprintf(stderr, "Notice: Directory 'sfm' already exists inside '~/.config'.\n");
            break;

        case DIR_ERR_CREATE_FAILED:
            fprintf(stderr, "Error: Failed to create 'sfm' directory.\n");
            break;
    }

    return EXIT_FAILURE;
}
*/