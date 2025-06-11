#ifndef UNICORN_RUNNER_H
#define UNICORN_RUNNER_H

#include <unicorn/unicorn.h>

/* Memory address wherer emulation starts.
 * For now, use a fixed address
 */
#define LOAD_ADDRESS 0x1000000


int load_program(uc_engine *uc, unsigned long load_address, const char *program_path, size_t *program_size);

uc_engine *init_unicorn(const char *program_path);
int start_emulation(uc_engine *uc);

#endif /* UNICORN_RUNNER_H */