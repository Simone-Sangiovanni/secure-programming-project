#include "cli.h"
#include <stdio.h>
#include <unistd.h> // POSIX getopt

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