#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"
#include "hooks.h"

#define STACK_TOP_ADDRESS 0xc000000

unsigned long load_address;
unsigned long stack_size;
size_t program_size = 0;


uc_engine *init_unicorn(const char *program_path, int program_argc, char *program_argv[])
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace;
    uint32_t r_esp;
    uint64_t stack_bottom, program_end_addr;

    printf("[>] Initialize Unicorn\n");

    /* Initialize emulator in x86 32bit mode */
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed on uc_open() with error returned: %u (%s)\n", err, uc_strerror(err));
        return NULL;
    }

    /* Load the program into memory */
    if (load_program(uc, load_address, program_path, &program_size) != 0) {
        fprintf(stderr, "Failed to load program in memory\n");
        uc_close(uc);
        return NULL;
    }

    /* Map the stack */
    stack_bottom = STACK_TOP_ADDRESS - stack_size;

    /* Check for overlapping with program code */
    program_end_addr = load_address + program_size;
    if (load_address < STACK_TOP_ADDRESS && program_end_addr > stack_bottom) {
        fprintf(stderr, "Memory overlap detected between program (0x%lx - 0x%lx) and stack (0x%lx - 0x%x)\n",
                load_address, program_end_addr -1, stack_bottom, STACK_TOP_ADDRESS -1);
        uc_close(uc);
        return NULL;
    }

    err = uc_mem_map(uc, stack_bottom, stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to map stack memory: %u (%s)\n", err, uc_strerror(err));
        uc_close(uc);
        return NULL;
    }
    r_esp = STACK_TOP_ADDRESS;
    printf("[!] Stack mapped at 0x%lx - 0x%x (size 0x%lx bytes)\n", stack_bottom, STACK_TOP_ADDRESS, stack_size);

    /* Initialize registers */
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);

    // Register hooks
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    return uc;
}

int start_emulation(uc_engine *uc)
{
    uc_err err;

    printf("[>] Start emulation...\n");

    // emulate code in infinite time & unlimited instructions
    err = uc_emu_start(uc, load_address, load_address + program_size, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
        uc_close(uc);
        return -1;
    }

    // ...

    printf("[>] Emulation finished\n");

    uc_close(uc);
    return 0;
}