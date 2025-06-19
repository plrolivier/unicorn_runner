#ifndef HOOKS_H
#define HOOKS_H
#include <unicorn/unicorn.h>

void print_registers(uc_engine *uc);
void print_stack(uc_engine *uc, uint32_t num_dwords);
void print_disassembled_code(uc_engine *uc, uint64_t address, uint32_t max_size, uint32_t num_instructions);
void print_memory_mappings(uc_engine *uc);

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_syscall(uc_engine *uc, uint32_t intno, void *user_data);

#endif /* HOOKS_H */