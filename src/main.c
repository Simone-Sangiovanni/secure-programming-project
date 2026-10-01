#include <stdio.h>
#include <stdlib.h>
#include "cli/cli.h"

int main(int argc, char *argv[]) {
    const CliStatus status = cli_parse(argc, argv);

    switch (status) {
        case CLI_EXIT_SUCCESS: return EXIT_SUCCESS;
        case CLI_ERROR: return EXIT_FAILURE;
        case CLI_OK: break; // proceed to run sfm
    }

    printf("Starting %s...\n", program_name);

    return EXIT_SUCCESS;
}