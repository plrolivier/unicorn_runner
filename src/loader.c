#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <unicorn/unicorn.h>

#include "unicorn_runner.h"


static unsigned long get_entrypoint(const unsigned char *buffer, size_t size)
{
    const Elf32_Ehdr *ehdr;

    if (size < sizeof(Elf32_Ehdr)) {
        fprintf(stderr, "Error: File size too small for ELF header\n");
        return 0;
    }

    ehdr = (const Elf32_Ehdr *)buffer;

    /* Basic ELF checks */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Error: Not an ELF file\n");
        return 0;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        fprintf(stderr, "Error: Not a 32-bit ELF file\n");
        return 0;
    }
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
         fprintf(stderr, "Error: Not a little-endian ELF file\n");
        return 0;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        fprintf(stderr, "Error: Not an executable or shared object ELF file (type %d)\n", ehdr->e_type);
        return 0;
    }
    if (ehdr->e_machine != EM_386) {
        fprintf(stderr, "Error: Not an x86 ELF file (machine %d)\n", ehdr->e_machine);
        return 0;
    }

    return ehdr->e_entry;
}

// For now, only works for **true** static ELF
int load_program(uc_engine *uc, struct program_info *pinfo)
{
    FILE *fp;
    long file_size;
    unsigned char *buffer;
    size_t bytes_read, mapped_program_size;
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

    buffer = (unsigned char*) malloc(file_size);
    if (!buffer) {
        perror("Faile to allocate memory buffer");
        fclose(fp);
        return -1;
    }

    bytes_read = fread(buffer, 1, file_size, fp);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "Faile to read file (read %zu instead of %ld)\n", bytes_read, file_size);
        free(buffer);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    /* Map memory */
    mapped_program_size = (file_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    err = uc_mem_map(uc, pinfo->base_address, mapped_program_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Fail to map program memory: %u (%s)\n", err, uc_strerror(err));
        free(buffer);
        return -1;
    }

    /* Write program to mapped memory */
    err = uc_mem_write(uc, pinfo->base_address, buffer, file_size);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Fail to load program into unicorn memory: %u (%s)\n", err, uc_strerror(err));
        free(buffer);
        return -1;
    }

    printf("[!] Program '%s' (%ld bytes) loaded @ 0x%lx\n", pinfo->path, file_size, pinfo->base_address);
    pinfo->size = (size_t) file_size;
    free(buffer);
    return 0;
}