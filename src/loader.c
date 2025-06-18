#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"


static int check_elf_header(const Elf32_Ehdr *ehdr)
{
    /* Basic ELF checks */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Error: Not an ELF file\n");
        return -1;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        fprintf(stderr, "Error: Not a 32-bit ELF file\n");
        return -1;
    }
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
         fprintf(stderr, "Error: Not a little-endian ELF file\n");
        return -1;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        fprintf(stderr, "Error: Not an executable or shared object ELF file (type %d)\n", ehdr->e_type);
        return -1;
    }
    if (ehdr->e_machine != EM_386) {
        fprintf(stderr, "Error: Not an x86 ELF file (machine %d)\n", ehdr->e_machine);
        return -1;
    }

    return 0;
}

// For now, only works for static ELF
int load_program(uc_engine *uc, struct program_info *pinfo)
{
    FILE *fp;
    long file_size;
    unsigned char *buffer;
    size_t bytes_read;
    const Elf32_Ehdr *ehdr;
    uint32_t load_offset;
    uint32_t actual_min_load_addr = -1ULL;
    uint32_t actual_max_load_addr_end = 0;
    uc_err err;

    /* Read program */
    fp = fopen(pinfo->path, "rb");
    if (!fp) {
        perror("Failed to read file");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < 0) {
        perror("Error while reading file size");
        fclose(fp);
        return -1;
    }

    if (file_size < sizeof(Elf32_Ehdr)) {
        fprintf(stderr, "Error: File size too small for ELF header\n");
        fclose(fp);
        return -1;
    }

    buffer = (unsigned char*) malloc(file_size);
    if (!buffer) {
        perror("Failed to allocate memory buffer");
        fclose(fp);
        return -1;
    }

    bytes_read = fread(buffer, 1, file_size, fp);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Failed to read file (read %zu instead of %ld)\n", bytes_read, file_size);
        free(buffer);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    /* Map memory */
    ehdr = (const Elf32_Ehdr *)buffer;

    if (check_elf_header(ehdr) != 0) {
        free(buffer);
        return -1;
    }

    load_offset = (ehdr->e_type == ET_DYN) ? pinfo->base_address : 0;
    printf("[!] Loading ELF program '%s' (type: %s)\n", pinfo->path, (ehdr->e_type == ET_DYN) ? "ET_DYN" : "ET_EXEC");

    /* Parse program header entries to load PT_LOAD ones */
    printf("\t  %-10s %-10s %-10s %-10s %-6s -> %-12s %-10s %-s\n",
           "VAddr", "MemSz", "FileSz", "Offset", "Flags", "Map Addr", "Map Size", "Perms");

    for (int i=0; i<ehdr->e_phnum; i++) {

        const Elf32_Phdr *phdr = (const Elf32_Phdr *)(buffer + ehdr->e_phoff + i * ehdr->e_phentsize);

        if (phdr->p_type == PT_LOAD) {

            if (phdr->p_memsz == 0) continue;

            uint64_t seg_actual_vaddr = load_offset + phdr->p_vaddr;

            /* Set segment addresses */
            uint64_t map_start_addr = seg_actual_vaddr & ~(PAGE_SIZE - 1);
            uint64_t map_end_addr = (seg_actual_vaddr + phdr->p_memsz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            uint64_t map_total_size = map_end_addr - map_start_addr;

            /* Set permissions */
            uint32_t uc_perms = 0;
            if (phdr->p_flags & PF_R) uc_perms |= UC_PROT_READ;
            if (phdr->p_flags & PF_W) uc_perms |= UC_PROT_WRITE;
            if (phdr->p_flags & PF_X) uc_perms |= UC_PROT_EXEC;

            /* Before mapping and writing, print some debug info */
            char flags_str[4] = "---";
            if (phdr->p_flags & PF_R) flags_str[0] = 'R';
            if (phdr->p_flags & PF_W) flags_str[1] = 'W';
            if (phdr->p_flags & PF_X) flags_str[2] = 'X';
            char perms_str[4] = "---";
            if (uc_perms & UC_PROT_READ) perms_str[0] = 'R';
            if (uc_perms & UC_PROT_WRITE) perms_str[1] = 'W';
            if (uc_perms & UC_PROT_EXEC) perms_str[2] = 'X';

            printf("\t  0x%08x 0x%-8x 0x%-8x 0x%-8x %-6s -> 0x%-10llx 0x%-8llx %-s\n",
                   phdr->p_vaddr, phdr->p_memsz, phdr->p_filesz, phdr->p_offset, flags_str,
                   (unsigned long long)map_start_addr, (unsigned long long)map_total_size, perms_str);


            /* Create the mapping in Unicorn */
            err = uc_mem_map(uc, map_start_addr, map_total_size, uc_perms);
            if (err != UC_ERR_OK) {
                fprintf(stderr, "Error mapping segment at 0x%llx (size 0x%llx): %u (%s)\n",
                        (unsigned long long)map_start_addr, (unsigned long long)map_total_size, err, uc_strerror(err));
                // A more robust loader might try to query existing mappings and merge/unmap if UC_ERR_MAP occurs.
                free(buffer);
                return -1;
            }

            /* Write the segment data in Unicorn */
            if (phdr->p_filesz > 0) {
                if (phdr->p_offset + phdr->p_filesz > (size_t)file_size) {
                    fprintf(stderr, "Error: segment file data (offset 0x%llx, size 0x%llx) out of bounds (file_size 0x%lx).\n",
                            (unsigned long long)phdr->p_offset, (unsigned long long)phdr->p_filesz, file_size);
                    free(buffer);
                    return -1;
                }

                err = uc_mem_write(uc, seg_actual_vaddr, buffer + phdr->p_offset, phdr->p_filesz);
                if (err != UC_ERR_OK) {
                    fprintf(stderr, "Error writing segment data at 0x%llx: %u (%s)\n",
                            (unsigned long long)seg_actual_vaddr, err, uc_strerror(err));
                    free(buffer);
                    return -1;
                }
            }

            if (seg_actual_vaddr < actual_min_load_addr) {
                actual_min_load_addr = seg_actual_vaddr;
            }
            if (seg_actual_vaddr + phdr->p_memsz > actual_max_load_addr_end) {
                actual_max_load_addr_end = seg_actual_vaddr + phdr->p_memsz;
            }
        }
    }

    if (actual_min_load_addr > actual_max_load_addr_end) { // No PT_LOAD segments found or all were empty
        fprintf(stderr, "Warning: No loadable segments found in ELF.\n");
        actual_min_load_addr = load_offset; // Default to load_offset if nothing loaded
        actual_max_load_addr_end = load_offset;
    }

    pinfo->base_address = actual_min_load_addr;
    pinfo->size = actual_max_load_addr_end - actual_min_load_addr;
    pinfo->entrypoint = load_offset + ehdr->e_entry;
    pinfo->phdr_addr = load_offset + ehdr->e_phoff;
    pinfo->phentsize = ehdr->e_phentsize;
    pinfo->phnum = ehdr->e_phnum;


    printf("[!] Program '%s' loaded. Effective Base: 0x%lx, Effective Size: 0x%zx, Entry Point: 0x%lx\n",
           pinfo->path, pinfo->base_address, pinfo->size, pinfo->entrypoint);

    free(buffer);
    return 0;
}