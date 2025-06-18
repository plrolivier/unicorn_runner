#ifndef UNICORN_RUNNER_H
#define UNICORN_RUNNER_H

#include <stddef.h>
#include <unicorn/unicorn.h>


#define DEFAULT_STACK_SIZE 1024 * 1024  // 1MB
#define DEFAULT_BASE_ADDRESS 0x1000000
#define PAGE_SIZE 0x1000


extern unsigned long stack_size;

struct program_info {
    const char *path;
    int argc;
    char **argv;
    size_t size;
    unsigned long base_address;
    unsigned long entrypoint;
    // ELF header info for auxv
    uint32_t phdr_addr; // Address of program header table in memory
    uint16_t phentsize; // Size of one program header entry
    uint16_t phnum;     // Number of program headers
};


int load_program(uc_engine *uc, struct program_info *pinfo);

uc_engine *init_unicorn(struct program_info *pinfo);
int start_emulation(uc_engine *uc, const struct program_info *pinfo);

#endif /* UNICORN_RUNNER_H */