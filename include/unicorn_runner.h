#ifndef UNICORN_RUNNER_H
#define UNICORN_RUNNER_H

#include <unicorn/unicorn.h>


#define DEFAULT_STACK_SIZE 1024 * 1024  // 1MB
#define DEFAULT_LOAD_ADDRESS 0x1000000
#define PAGE_SIZE 0x1000

/* Memory address where emulation starts.
 */
extern unsigned long load_address;
extern unsigned long stack_size;


int load_program(uc_engine *uc, unsigned long load_address, const char *program_path, size_t *program_size);

uc_engine *init_unicorn(const char *program_path, int program_argc, char *program_argv[]);
int start_emulation(uc_engine *uc);

#endif /* UNICORN_RUNNER_H */