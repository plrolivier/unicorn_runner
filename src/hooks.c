#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>

#include "hooks.h"


#define MIN(a, b) (a < b ? a : b)


void print_registers(uc_engine *uc) {
    uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags;

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_ESI, &esi);
    uc_reg_read(uc, UC_X86_REG_EDI, &edi);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EIP, &eip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);

    printf("[!] Registers\n");
    printf("    EAX: 0x%08" PRIx32 "  EBX: 0x%08" PRIx32 "  ECX: 0x%08" PRIx32 "  EDX: 0x%08" PRIx32 "\n", eax, ebx, ecx, edx);
    printf("    ESI: 0x%08" PRIx32 "  EDI: 0x%08" PRIx32 "  EBP: 0x%08" PRIx32 "  ESP: 0x%08" PRIx32 "\n", esi, edi, ebp, esp);
    printf("    EIP: 0x%08" PRIx32 "  EFLAGS: 0x%08" PRIx32 "\n", eip, eflags);
}

void print_stack(uc_engine *uc, uint32_t esp_val, uint32_t num_dwords) {
    if (num_dwords == 0) {
        return;
    }

    printf("[!] Stack\n");
    uint32_t stack_val;
    uc_err err;

    for (uint32_t i = 0; i < num_dwords; ++i) {
        uint32_t current_addr = esp_val + (i * sizeof(uint32_t));
        err = uc_mem_read(uc, current_addr, &stack_val, sizeof(stack_val));
        if (err == UC_ERR_OK) {
            printf("    0x%08" PRIx32 ": 0x%08" PRIx32 "\n", current_addr, stack_val);
        } else {
            printf("    0x%08" PRIx32 ": <Read Error: %s>\n", current_addr, uc_strerror(err));
            break;
        }
    }
}

void print_disassembled_code(uc_engine *uc, uint64_t address, uint32_t max_size, uint32_t num_instructions) {
    csh handle;
    cs_insn *insn;
    size_t count;
    uc_err err;
    unsigned char *buffer;

    // Capstone recommends a buffer slightly larger than needed for safety.
    // Max x86 instruction length is 15 bytes.
    uint32_t read_size = MIN(max_size, num_instructions * 15 + 16);
    if (read_size == 0) return;

    buffer = (unsigned char *)malloc(read_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer for disassembly\n");
        return;
    }

    err = uc_mem_read(uc, address, buffer, read_size);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to read memory for disassembly at 0x%"PRIx64": %s\n", address, uc_strerror(err));
        free(buffer);
        return;
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        free(buffer);
        return;
    }

    printf("[!] Disassembly\n");
    count = cs_disasm(handle, buffer, read_size, address, num_instructions, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            printf("    0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("    <Failed to disassemble code at 0x%"PRIx64">\n", address);
    }

    cs_close(&handle);
    free(buffer);
}

void print_memory_mappings(uc_engine *uc) {
    uc_mem_region *regions;
    uint32_t count;
    uc_err err;

    printf("[!] Memory Mappings:\n");
    err = uc_mem_regions(uc, &regions, &count);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to retrieve memory regions: %s\n", uc_strerror(err));
        return;
    }

    if (count == 0) {
        printf("    No memory regions mapped.\n");
        return;
    }

    printf("    %-12s %-10s  %-10s %-6s\n", "Start", "End", "Size", "Perms");
    for (uint32_t i = 0; i < count; i++) {
        char perms_str[4] = "---";
        if (regions[i].perms & UC_PROT_READ) perms_str[0] = 'R';
        if (regions[i].perms & UC_PROT_WRITE) perms_str[1] = 'W';
        if (regions[i].perms & UC_PROT_EXEC) perms_str[2] = 'X';

        uint64_t region_size = regions[i].end - regions[i].begin + 1;
        printf("    0x%08"PRIx64" - 0x%08"PRIx64"  0x%-8"PRIx64" %s\n",
                regions[i].begin, regions[i].end, region_size, perms_str);
    }
    uc_free(regions); // allocated by uc_mem_regions
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint32_t r_eip, r_esp;
    uint8_t tmp[16];

    printf("-----------------------------------------------------------------\n");
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

    print_registers(uc);
    uc_reg_read(uc, UC_X86_REG_ESP, &r_esp);
    print_stack(uc, r_esp, 8);
    print_disassembled_code(uc, address, 64, 5);
    print_memory_mappings(uc);
}
