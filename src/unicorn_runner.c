#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"
#include "hooks.h"

#define STACK_TOP_ADDRESS 0xc000000

unsigned long stack_size;


uc_engine *init_unicorn(struct program_info *pinfo)
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
    if (load_program(uc, pinfo) != 0) {
        fprintf(stderr, "Failed to load program in memory\n");
        uc_close(uc);
        return NULL;
    }

    /* Map the stack */
    stack_bottom = STACK_TOP_ADDRESS - stack_size;

    /* Check for overlapping with program code */
    program_end_addr = pinfo->base_address + pinfo->size;
    if (pinfo->base_address < STACK_TOP_ADDRESS && program_end_addr > stack_bottom) {
        fprintf(stderr, "Memory overlap detected between program (0x%lx - 0x%lx) and stack (0x%lx - 0x%x)\n",
                pinfo->base_address, program_end_addr -1, stack_bottom, STACK_TOP_ADDRESS -1);
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
    // todo

    // Register hooks
    uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    return uc;
}

int start_emulation(uc_engine *uc, const struct program_info *pinfo)
{
    uc_err err;

    printf("[>] Start emulation...\n");

    // emulate code in infinite time & unlimited instructions
    // TODO: verify if values makes sense here... take the size of the code segment.
    err = uc_emu_start(uc, pinfo->entrypoint, pinfo->base_address + pinfo->size, 0, 0);
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