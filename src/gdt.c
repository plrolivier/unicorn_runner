#include <string.h>
#include <errno.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"
#include "gdt.h"


/* Keep track of free TLS entries in the GDT */
bool free_tls_entries[GDT_ENTRY_TLS_ENTRIES] = {1};


int gdt_init(uc_engine *uc)
{
    uc_x86_mmr gdtr;
    uc_err err;

    /* Map and zero GDT into unicorn memory */
    err = uc_mem_map(uc, GDT_BASE_ADDRESS, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to map GDT memory in Unicorn at 0x%llx: %s\n", GDT_BASE_ADDRESS, uc_strerror(err));
        return -1;
    }

    unsigned char *zero_buffer = (unsigned char *)calloc(GDT_SIZE, 1);
    if (!zero_buffer) {
        fprintf(stderr, "Failed to allocate zero-buffer for GDT initialization (size: %lu)\n", GDT_SIZE);
        return -1;
    }

    err = uc_mem_write(uc, GDT_BASE_ADDRESS, zero_buffer, GDT_SIZE);
    free(zero_buffer);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to initialize GDT with zeroes: %u (%s)\n", err, uc_strerror(err));
        return -1;
    }

    /* Set GDTR register */
    gdtr.base = GDT_BASE_ADDRESS;
    gdtr.limit = GDT_SIZE - 1;
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to write GDTR: %s\n", uc_strerror(err));
        return -1;
    }

    return 0;
}


unsigned int gdt_get_tls_index(void)
{
    unsigned int idx;

    for (idx=0; idx<GDT_ENTRY_TLS_ENTRIES; idx++) {
        if (free_tls_entries[idx]) {
            return idx + GDT_ENTRY_TLS_MIN;
        }
    }
    return -ESRCH;
}

int gdt_allocate_tls_entry(uc_engine *uc, const struct user_desc *u_info, unsigned int index)
{
    struct segment_descriptor sd;
    uint32_t limit;
    uint8_t access, type;
    uint64_t gdt_entry_addr;
    uc_err err;

    memset(&sd, 0, sizeof(struct segment_descriptor));

    /* Base address on 32 bits */
    sd.base_low = u_info->base_addr & 0xFFFF;
    sd.base_middle = (u_info->base_addr >> 16) & 0xFF;
    sd.base_high = (u_info->base_addr >> 24) & 0xFF;

    /* Limit on 20 bits */
    limit = (u_info->limit > 0xFFFF) ? 0xFFFF : u_info->limit;
    sd.limit_low = limit & 0xFFFF;
    sd.limit_high_flags = (limit >> 16) & 0x0F;
    if (u_info->limit_in_pages)  {
        sd.limit_high_flags |= (1 << 7);   // set G bit (Granularity)
    }
    if (u_info->useable) {
        sd.limit_high_flags |= (1 << 4);   // set AVL bit
    }
    if (u_info->seg_32bit) {
        sd.limit_high_flags |= (1 << 6);   // D/B bit
    }

    /* Access byte: P(1) DPL(2) S(1) Type(4) */
    access = 0;
    if (!u_info->seg_not_present) {
        access |= (1 << 7);
    }
    access |= (3 << 5);
    access |= (1 << 4);

    type = 0;
    switch (u_info->contents) {
        case 0:     // data
            type = u_info->read_exec_only ? 0b0000 : 0b0010;    // ED=0, W=0/1, A=0
            break;
        case 1:     // stack
            type = u_info->read_exec_only ? 0b0100 : 0b0110;    // ED=1, W=0/1, A=0
        case 2:     // code
            type = u_info->read_exec_only ? 0b1000 : 0b1010;    //  C=0, R=0/1, A=0
    }
    access |= type;
    sd.access = access;

    /* Write to GDT */
    gdt_entry_addr = GDT_BASE_ADDRESS + (index * sizeof(struct segment_descriptor));
    err = uc_mem_write(uc, gdt_entry_addr, &sd, sizeof(struct segment_descriptor));
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to write GDT entry %u @ 0x%llx: %s\n", index, gdt_entry_addr, uc_strerror(err));
        return -1;
    }

    return 0;
}