#ifndef GDT_H
#define GDT_H

#include <stdint.h>

// from <asm/ldt.h>
struct user_desc {
    unsigned int  entry_number;
    unsigned int  base_addr;
    unsigned int  limit;
    unsigned int  seg_32bit:1;
    unsigned int  contents:2;
    unsigned int  read_exec_only:1;
    unsigned int  limit_in_pages:1;
    unsigned int  seg_not_present:1;
    unsigned int  useable:1;
    unsigned int  lm:1;     // long mode (64-bit)
};

/* Segment Descriptor on 8 bytes
 * See Intel Manual vol. 3a figure 3-8
 */
struct segment_descriptor {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  limit_high_flags; // Includes limit high (4 bits) and flags (4 bits)
    uint8_t  base_high;
} __attribute__((packed));

#define GDT_BASE_ADDRESS 0xfffff000
#define GDT_NB_ENTRIES 16
#define GDT_SIZE (GDT_NB_ENTRIES * sizeof(struct segment_descriptor))
#define GDT_ENTRY_TLS_ENTRIES 3
#define GDT_ENTRY_TLS_MIN 6     // 6 for 32-bits, 12 for 64 bits
#define GDT_ENTRY_TLS_MAX (GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1)


int gdt_init(uc_engine *uc);
unsigned int gdt_get_tls_index(void);
int gdt_allocate_tls_entry(uc_engine *uc, const struct user_desc *u_info, unsigned int index);

#endif  /* GDT_H */
