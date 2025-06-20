#include <stdio.h>
#include <errno.h>
#include <unicorn/unicorn.h>

#include "syscalls.h"
#include "gdt.h"



void handle_sys_set_thread_area(uc_engine *uc, struct syscall *sc)
{
    unsigned int idx;
    uint32_t u_info_addr;
    struct user_desc u_info;
    uc_err err;

    u_info_addr = sc->args[0];
    printf("[!] set_thread_area(u_info=0x%x)\n", u_info_addr);

    /* Read user_desc from memory */
    err = uc_mem_read(uc, u_info_addr, &u_info, sizeof(u_info));
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to read user_desc @ 0x%x: %s\n", u_info_addr, uc_strerror(err));
        sc->retval = (uint32_t)-EFAULT;
        return;
    }

    /* Get an unused index */
    idx = gdt_get_tls_index();
    if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX) {
        sc->retval = (uint32_t)-EFAULT;
        return;
    }

    /* Write the selected GDT entry into memory */
    if (u_info.entry_number == -1) {
        u_info.entry_number = idx;
        err = uc_mem_write(uc,
                           (uint64_t)&((struct user_desc *)u_info_addr)->entry_number,
                           &u_info.entry_number,
                           sizeof(u_info.entry_number));
        if (err != UC_ERR_OK) {
            fprintf(stderr, "Failed to write user_desc->entry_number @ 0x%x: %s\n",
                &((struct user_desc *)u_info_addr)->entry_number, uc_strerror(err));
            sc->retval = (uint32_t)-EFAULT;
            return;
        }
    }

    /* Populate the GDT with the TLS entry */
    gdt_allocate_tls_entry(&u_info, idx);

    /* Return success */
    sc->retval = 0;
}
