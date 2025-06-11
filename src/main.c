#include <stdio.h>
#include "unicorn_runner.h"

int main(int argc, char *argv[])
{
    uc_engine *uc;

    printf("=== Unicorn runner 3000 ===\n");

    uc = init_unicorn("./samples/x86_code32_self");
    if (uc == NULL) {
        return -1;
    }

    start_emulation(uc);

    return 0;
}
