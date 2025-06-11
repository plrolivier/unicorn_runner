#ifndef HOOKS_H
#define HOOKS_H
#include <unicorn/unicorn.h>

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

#endif /* HOOKS_H */