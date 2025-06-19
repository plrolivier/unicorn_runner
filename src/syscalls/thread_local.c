#include <stdio.h>
#include <unicorn/unicorn.h>

#include "syscalls.h"



void handle_sys_set_thread_area(uc_engine *uc, struct syscall *sc)
{
    uint32_t u_info_addr = sc->args[0];

    printf("[!] set_thread_area(u_info=0x%x)\n", u_info_addr);

    // not implemented
    sc->retval = 0;
}
