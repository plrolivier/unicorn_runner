#include <stdio.h>
#include <errno.h>
#include <sys/resource.h>
#include <unicorn/unicorn.h>

#include "syscalls.h"
#include "unicorn_runner.h"
#include "hooks.h"



static uint32_t tid_address = 0;


void handle_sys_set_tid_address(uc_engine *uc, struct syscall *sc)
{
    uint32_t tidptr_addr = sc->args[0];

    printf("[!] set_tid_address(tidptr=0x%x)\n", tidptr_addr);

    // Return a dummy TID 
    sc->retval = 1;
}

void handle_sys_set_robust_list(uc_engine *uc, struct syscall *sc)
{
    uint32_t head_addr = sc->args[0];
    size_t len = (size_t)sc->args[1];

    printf("[!] set_robust_list(head=0x%x, len=%zu)\n", head_addr, len);

    // not implemented
    sc->retval = 0;
}

void handle_sys_rseq(uc_engine *uc, struct syscall *sc)
{
    uint32_t rseq_addr = sc->args[0];
    uint32_t rseq_len = sc->args[1];
    uint32_t flags = sc->args[2];
    uint32_t sig = sc->args[3];

    printf("[!] rseq(rseq=0x%x, len=%u, flags=0x%x, sig=0x%x)\n",
           rseq_addr, rseq_len, flags, sig);

    // not implemented
    sc->retval = (uint32_t)-ENOSYS;
}

void handle_sys_ugetrlimit(uc_engine *uc, struct syscall *sc)
{
    int resource = (int)sc->args[0];
    uint32_t rlim_addr = sc->args[1];

    printf("[!] ugetrlimit(resource=%d, rlim=0x%x)\n", resource, rlim_addr);

    // not implemented
    // do not emulate 
    sc->retval = (uint32_t)-EFAULT;
}