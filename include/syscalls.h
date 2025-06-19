#ifndef SYSCALL_H
#define SYSCALL_H
#include <unicorn/unicorn.h>
#include <inttypes.h>


struct syscall {
    uint32_t no;
    uint32_t args[6];
    uint32_t retval;
};


/* Linux x86 32-bit syscall numbers
 * https://syscalls.mebeim.net/
 */
#define SYS_RESTART_SYSCALL 0
#define SYS_EXIT    0x1
#define SYS_FORK    0x2
#define SYS_READ    0x3
#define SYS_WRITE   0x4
#define SYS_OPEN    0x5
#define SYS_CLOSE   0x6
#define SYS_WAITPID 0x7
#define SYS_CREAT   0x8
#define SYS_LINK    0x9
#define SYS_UNLINK  0xa
#define SYS_EXECVE  0xb
#define SYS_CHDIR   0xc
#define SYS_TIME    0xd
#define SYS_MKNOD   0xe
#define SYS_CHMOD   0xf
#define SYS_LCHOWN16    0x10
#define SYS_STAT    0x11
#define SYS_LSEEK   0x12
#define SYS_GETPID  0x14

#define SYS_BRK     0x2d
#define SYS_MPROTECT    0x7d

#define SYS_UGETRLIMIT  0x4c

#define SYS_READLINKAT 0x55
#define SYS_MMAP    0x5a
#define SYS_MUNMAP  0x5b

#define SYS_SET_THREAD_AREA 0xf3
#define SYS_EXIT_GROUP 0xfc

#define SYS_SET_TID_ADDRESS 0x102
#define SYS_SET_ROBUST_LIST 0x137
#define SYS_GETRANDOM 0x163
#define SYS_RSEQ 0x182


#define MAP_FAILED ((void *)-1)


void init_brk(uint64_t initial_brk);

void handle_sys_exit(uc_engine *uc, struct syscall *sc);
void handle_sys_brk(uc_engine *uc, struct syscall *sc);
void handle_sys_set_thread_area(uc_engine *uc, struct syscall *sc);
void handle_sys_set_tid_address(uc_engine *uc, struct syscall *sc);
void handle_sys_set_robust_list(uc_engine *uc, struct syscall *sc);
void handle_sys_rseq(uc_engine *uc, struct syscall *sc);
void handle_sys_ugetrlimit(uc_engine *uc, struct syscall *sc);
//void handle_sys_readlinkat(uc_engine *uc, struct syscall *sc);
//void handle_sys_getrandom(uc_engine *uc, struct syscall *sc);
void handle_sys_mprotect(uc_engine *uc, struct syscall *sc);

#endif  /* SYSCALL_H */