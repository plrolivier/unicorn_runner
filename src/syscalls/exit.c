#include <stdio.h>
#include <unicorn/unicorn.h>

#include "syscalls.h"



void handle_sys_exit(uc_engine *uc, struct syscall *sc)
{
    printf("[!] %s(%d)\n", (sc->no == SYS_EXIT) ? "exit" : "exit_group", sc->args[0]);
    uc_emu_stop(uc);
    sc->retval = 0; 
}
