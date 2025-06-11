#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"
#include "hooks.h"

size_t program_len = 0;


uc_engine *init_unicorn(const char *program_path)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace;
    int r_esp = LOAD_ADDRESS + 0x200000;

    printf("[>] Initialize Unicorn\n");

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return NULL;
    }

    // Map 2MB memory for this emulation
    uc_mem_map(uc, LOAD_ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // Write machine code to be emulated to memory
    if (load_program(uc, LOAD_ADDRESS, program_path, &program_len) != 0) {
        fprintf(stderr, "Failed to load program in memory\n");
        uc_close(uc);
        return NULL;
    }

    // Initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

    // Register hooks
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    return uc;
}

int start_emulation(uc_engine *uc)
{
    uc_err err;

    printf("[>] Start emulation\n");

    // emulate code in infinite time & unlimited instructions
    err = uc_emu_start(uc, LOAD_ADDRESS, LOAD_ADDRESS + program_len, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
        return -1;
    }

    // now print out some registers
    printf("[>] Emulation finished\n");

    uc_close(uc);
    return 0;
}