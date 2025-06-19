#include <stdio.h>
#include <stddef.h>
#include <unicorn/unicorn.h>

#include "syscalls.h"
#include "unicorn_runner.h"
#include "hooks.h"



static uint64_t program_break = 0;


void init_brk(uint64_t initial_brk_val) {
    program_break = initial_brk_val;
}

void handle_sys_brk(uc_engine *uc, struct syscall *sc)
{
    uc_err err;
    uint32_t addr;
    uint64_t aligned_new_brk, aligned_current_brk, map_start;
    size_t map_size;
    
    addr = sc->args[0];
    printf("[!] brk(addr=0x%x)\n", addr);

    /* Calling with 0x0 is used to find the current location of program break,
     * otherwise allocate memory on the heap
     */
    if (addr != 0) {
        aligned_new_brk = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        aligned_current_brk = (program_break + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

        if (addr > program_break) {
            /* Do we need to extend the current mapping? */
            if (aligned_new_brk > aligned_current_brk) {
                map_start = aligned_current_brk;
                map_size = aligned_new_brk - aligned_current_brk;

                err = uc_mem_map(uc, map_start, map_size, UC_PROT_READ | UC_PROT_WRITE);
                if (err != UC_ERR_OK) {
                    fprintf(stderr, "[-] SYS_BRK: uc_mem_map failed to extend heap (0x%llx, 0x%zx): %s\n",
                            (unsigned long long)map_start, map_size, uc_strerror(err));
                    sc->retval = (uint32_t)program_break;
                }

                printf("[!] Mapped 0x%zx bytes at 0x%llx for heap\n", map_size, (unsigned long long)map_start);
                unsigned char *zero_buffer = (unsigned char *)calloc(map_size, 1);
                if (!zero_buffer) {
                    fprintf(stderr, "Failed to allocate zero-buffer for extending heap (size: %lu)\n", map_size);
                } else {
                    uc_mem_write(uc, map_start, zero_buffer, map_size);
                    free(zero_buffer);
                }
                print_memory_mappings(uc);
            }
        }
        program_break = addr;
    }

    sc->retval = (uint32_t)program_break;
}


void handle_sys_mprotect(uc_engine *uc, struct syscall *sc)
{
    uint32_t addr = sc->args[0];
    size_t len = (size_t)sc->args[1];
    int prot = (int)sc->args[2];

    printf("[!] mprotect(addr=0x%x, len=0x%zx, prot=0x%x)\n", addr, len, prot);

    // not implemented
    sc->retval = 0;
}