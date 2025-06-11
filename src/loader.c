#include <stdlib.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include "unicorn_runner.h"

// For now, only works for static binaries
int load_program(uc_engine *uc, unsigned long load_address, const char *program_path, size_t *program_size)
{
    FILE *fp;
    long file_size;
    unsigned char *buffer;
    size_t bytes_read;
    uc_err err;

    fp = fopen(program_path, "rb");
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

    err = uc_mem_write(uc, load_address, buffer, file_size);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Fail to load program into unicorn memory: %u (%s)\n", err, uc_strerror(err));
        free(buffer);
        return -1;
    }

    printf("[!] Program '%s' (%ld bytes) loaded @ 0x%lx\n", program_path, file_size, load_address);
    *program_size = (size_t) file_size;
    free(buffer);
    return 0;
}