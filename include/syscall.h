#ifndef SYSCALL_H
#define SYSCALL_H
#include <unicorn/unicorn.h>
#include <inttypes.h>


struct syscall {
    uint32_t no;
    uint32_t args[6];
    uint32_t retval;
};


// Linux x86 32-bit syscall numbers
#define SYS_EXIT 1
#define SYS_WRITE 4
#define SYS_BRK 45
#define SYS_UNAME 122
#define SYS_MMAP2 192
#define SYS_EXIT_GROUP 252

// Value for mmap2 failure
#define MAP_FAILED ((void *)-1)


void init_brk(uint64_t initial_brk);

void handle_sys_exit(uc_engine *uc, struct syscall *sc);
void handle_sys_brk(uc_engine *uc, struct syscall *sc);

#endif  /* SYSCALL_H */