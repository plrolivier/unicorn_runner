#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"
#include "hooks.h"
#include "syscalls.h"

#define STACK_TOP_ADDRESS 0xc000000

unsigned long stack_size;


/* Helper functions to write to stack
 */
static uint32_t write_string_to_stack(uc_engine *uc, uint32_t current_esp, const char *str)
{
    size_t len = strlen(str) + 1;
    current_esp -= len;

    uc_err err = uc_mem_write(uc, current_esp, str, len);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to write string '%s' to stack at 0x%x: %s\n", str, current_esp, uc_strerror(err));
        return 0;
    }
    return current_esp;
}

static uint32_t write_dword_to_stack(uc_engine *uc, uint32_t current_esp, uint32_t value)
{
    current_esp -= sizeof(uint32_t);

    uc_err err = uc_mem_write(uc, current_esp, &value, sizeof(uint32_t));
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to write dword 0x%x to stack at 0x%x: %s\n", value, current_esp, uc_strerror(err));
        return 0;
    }
    return current_esp;
}

static int setup_stack(uc_engine *uc, struct program_info *pinfo, uint32_t *initial_esp)
{
    uint32_t esp = STACK_TOP_ADDRESS;
    uint32_t execfn_addr, random_bytes_addr;
    uint32_t argv_str_addr[pinfo->argc + 1];

    /*
     * 1. Write stings content to stack
     */
    esp = write_string_to_stack(uc, esp, pinfo->path);
    if (esp == 0) return -1;
    argv_str_addr[0] = esp;
    execfn_addr = esp;

    for (int i=0; i<pinfo->argc; i++) {
        esp = write_string_to_stack(uc, esp, pinfo->argv[i]);
        if (esp == 0) return -1;
        argv_str_addr[i+1] = esp;
    }

    // Align stack point to 4-byte
    esp &= ~0x3;
    // Padding
    esp -= 16;

    /*
     * 2. Write auxiliary vector (auxv)
     */
    random_bytes_addr = esp;
    Elf32_auxv_t aux_val[] = {
       {AT_RANDOM,  {.a_val = random_bytes_addr}},
       {AT_PAGESZ,  {.a_val = PAGE_SIZE}},
       {AT_PHDR,    {.a_val = pinfo->phdr_addr}},
       {AT_PHENT,   {.a_val = pinfo->phentsize}},
       {AT_PHNUM,   {.a_val = pinfo->phnum}},
       {AT_ENTRY,   {.a_val = pinfo->entrypoint}},
       {AT_EXECFN,  {.a_val = execfn_addr}},
       {AT_NULL,    {.a_val = 0}},
    };

    for (int i=sizeof(aux_val)-1; i>=0; i--) {
        esp = write_dword_to_stack(uc, esp, aux_val[i].a_un.a_val);
        if (esp == 0) return -1;
        esp = write_dword_to_stack(uc, esp, aux_val[i].a_type);
        if (esp == 0) return -1;
    }

    /*
     * 3. Write environment pointers (envp)
     */
    // For now, empty environment with NULL terminator
    esp = write_dword_to_stack(uc, esp, 0);
    if (esp == 0) return -1;

    /*
     * 4. Write argument pointers (argv)
     */
    esp = write_dword_to_stack(uc, esp, 0);
    if (esp == 0) return -1;

    for (int i=pinfo->argc; i>=0; i--) {
        esp = write_dword_to_stack(uc, esp, argv_str_addr[i]);
        if (esp == 0) return -1;
    }

    /*
     * 5. Write argc
     */
    esp = write_dword_to_stack(uc, esp, pinfo->argc + 1);
    if (esp == 0) return -1;

    *initial_esp = esp;
    return 0;
}

static uint32_t init_stack(uc_engine *uc, struct program_info *pinfo)
{
    uc_err err;
    uint64_t stack_bottom, program_end_addr;
    uint32_t r_esp;

    stack_bottom = STACK_TOP_ADDRESS - stack_size;

    /* Check for overlapping with program code */
    program_end_addr = pinfo->base_address + pinfo->size;
    if (pinfo->base_address < STACK_TOP_ADDRESS && program_end_addr > stack_bottom) {
        fprintf(stderr, "Memory overlap detected between program (0x%lx - 0x%lx) and stack (0x%lx - 0x%x)\n",
                pinfo->base_address, program_end_addr -1, stack_bottom, STACK_TOP_ADDRESS -1);
        return 0;
    }

    /* Map the stack and initialize with zeroes */
    err = uc_mem_map(uc, stack_bottom, stack_size, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to map stack memory: %u (%s)\n", err, uc_strerror(err));
        return 0;
    }

    unsigned char *zero_buffer = (unsigned char *)calloc(stack_size, 1);
    if (!zero_buffer) {
        fprintf(stderr, "Failed to allocate zero-buffer for stack initialization (size: %lu)\n", stack_size);
        return 0;
    }

    err = uc_mem_write(uc, stack_bottom, zero_buffer, stack_size);
    free(zero_buffer);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to initialize stack memory with zeroes: %u (%s)\n", err, uc_strerror(err));
        return 0;
    }

    if (setup_stack(uc, pinfo, &r_esp) != 0) {
        fprintf(stderr, "Failed to setup stack\n");
        return 0;
    }
    printf("[!] Stack mapped at 0x%lx - 0x%x (size 0x%lx bytes)\n", stack_bottom, STACK_TOP_ADDRESS - 1, stack_size);

    return r_esp;
}

static int init_heap(uc_engine *uc, struct program_info *pinfo)
{
    /* Set the brk to the end of BSS segment */
    init_brk(pinfo->base_address + pinfo->size);
    return 0;
}

static int init_regs(uc_engine *uc, uint32_t esp, uint32_t eflags)
{
    // TODO: add error handling here
    uint32_t zero_val = 0;

    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);

    uc_reg_write(uc, UC_X86_REG_EAX, &zero_val);
    uc_reg_write(uc, UC_X86_REG_EBX, &zero_val);
    uc_reg_write(uc, UC_X86_REG_ECX, &zero_val);
    uc_reg_write(uc, UC_X86_REG_EDX, &zero_val);
    uc_reg_write(uc, UC_X86_REG_ESI, &zero_val);
    uc_reg_write(uc, UC_X86_REG_EDI, &zero_val);
    uc_reg_write(uc, UC_X86_REG_EBP, &zero_val);

    return 0;
}


uc_engine *init_unicorn(struct program_info *pinfo)
{
    uc_engine *uc;
    uc_err err;
    uc_hook hk_code, hk_int;
    uint32_t r_esp;

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

    /* Initialize stack */
    r_esp = init_stack(uc, pinfo);
    if (r_esp == 0) {
        fprintf(stderr, "Failed to initialize stack memory\n");
        uc_close(uc);
        return NULL;
    }

    /* Initialize heap */
    if (init_heap(uc, pinfo) != 0) {
        fprintf(stderr, "Failed to initialize heap memory\n");
        uc_close(uc);
        return NULL;
    }

    /* Initialize registers */
    if (init_regs(uc, r_esp, 0) !=0) {
        fprintf(stderr, "Failed to initialize registers\n");
        uc_close(uc);
        return NULL;
    }

    /* Register hooks */
    uc_hook_add(uc, &hk_code, UC_HOOK_CODE, hook_code, NULL, 1, 0);
    uc_hook_add(uc, &hk_int, UC_HOOK_INTR, hook_int, NULL, 1, 0);

    /* Some debugging info */
    print_memory_mappings(uc);
    print_registers(uc);
    print_stack(uc, 8);

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
        print_registers(uc);
        print_stack(uc, 8);
        print_memory_mappings(uc);
        uc_close(uc);
        return -1;
    }

    // ...

    printf("[>] Emulation finished\n");

    uc_close(uc);
    return 0;
}