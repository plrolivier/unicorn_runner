#include "hooks.h"

#define MIN(a, b) (a < b ? a : b)

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int r_eip;
    uint8_t tmp[16];

    printf("Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n",
           address, size);

    uc_reg_read(uc, UC_X86_REG_EIP, &r_eip);
    printf("*** EIP = %x ***: ", r_eip);

    size = MIN(sizeof(tmp), size);
    if (!uc_mem_read(uc, address, tmp, size)) {
        uint32_t i;
        for (i = 0; i < size; i++) {
            printf("%x ", tmp[i]);
        }
        printf("\n");
    }
}