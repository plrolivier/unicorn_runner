#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include "unicorn_runner.h"


static void  print_usage(const char *prog_name, FILE *stream)
{
    fprintf(stream, "Usage: %s [options] <program> <program args>\n", prog_name);
    fprintf(stream, "Emulates ELF static binaries using the Unicorn Engine.\n\n");
    fprintf(stream, "Arguments:\n");
    fprintf(stream, "  <program>                Path to the raw binary file to emulate.\n\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  -h, --help               Display this help message and exit.\n");
    fprintf(stream, "  -B, --address address    Set the load address (default: 0x%x)\n", DEFAULT_LOAD_ADDRESS);
    fprintf(stream, "  -s, --size size          Set stack size (default 1MB)\n");
}


int main(int argc, char *argv[])
{
    uc_engine *uc;
    unsigned long parsed_load_address = DEFAULT_LOAD_ADDRESS;
    unsigned long parsed_stack_size = DEFAULT_STACK_SIZE;
    const char *program_path = NULL;
    int program_argc = 0;
    char **program_argv = NULL;
    int opt;
    char *endptr;

    static struct option long_options[] = {
        {"help",    no_argument,        0, 'h'},
        {"address", required_argument,  0, 'B'},
        {"size",    required_argument,  0, 's'},
        {0, 0, 0, 0}
    };
    int option_index = 0;

    if (argc < 2) {
        print_usage(argv[0], stdout);
        return EXIT_SUCCESS;
    }

    /* Argument parsing */
    while ((opt = getopt_long(argc, argv, "hB:s:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0], stdout);
                return EXIT_SUCCESS;
            
            case 'B':
                errno = 0;
                parsed_load_address = strtoul(optarg, &endptr, 0);
                if (errno == ERANGE || *endptr != '\0' || optarg == endptr) {
                    fprintf(stderr, "Error: Invalid address for -B: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;
            
            case 's':
                errno = 0;
                parsed_stack_size = strtoul(optarg, &endptr, 10);
                if (errno == ERANGE || *endptr != '\0' || optarg == endptr) {
                    fprintf(stderr, "Error: Invalid size for -s: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                break;

            
            default:
                print_usage(argv[0], stderr);
                return EXIT_FAILURE;
        }
    }

    load_address = parsed_load_address;
    stack_size = parsed_stack_size;

    /* The remaining are the program path and its arguments */
    if (optind >= argc) {
        print_usage(argv[0], stderr);
        return EXIT_FAILURE;
    }
    program_path = argv[optind];
    optind++;

    if (optind < argc) {
        program_argc = argc - optind;
        program_argv = &argv[optind];
    }

    /* Let's start the emulation! */
    printf("=== Unicorn runner 3000 ===\n");

    uc = init_unicorn(program_path, program_argc, program_argv);
    if (uc == NULL) {
        return EXIT_FAILURE;
    }

    if (start_emulation(uc) != 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
