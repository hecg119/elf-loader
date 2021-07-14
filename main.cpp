#include "elf/loader.h"
#include <common/log.h>

int main(int argc, char **argv) {
    INIT_CONSOLE_LOG(INFO);

    if (argc < 2) {
        LOG_ERROR("require input file");
        return -1;
    }

    ELFLoader loader;

    if (!loader.load(argv[1]))
        return -1;

    loader.jump(argc - 1, argv + 1);

    return 0;
}
