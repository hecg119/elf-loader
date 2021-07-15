#include "loader.h"
#include <unistd.h>
#include <sys/mman.h>
#include <common/log.h>
#include <elf.h>

ELFLoader::ELFLoader() {
    mPagesize = sysconf(_SC_PAGESIZE);
}

bool ELFLoader::load(const std::string &file) {
    ELFIO::elfio reader;

    if (!reader.load(file))
        return false;

    auto it = std::find_if(
            reader.segments.begin(),
            reader.segments.end(),
            [](const auto& s) {
                return s->get_type() == PT_INTERP;
            });

    if (it != reader.segments.end()) {
        const char * interpreter = (*it)->get_data();

        if (!loadInterpreter(interpreter)) {
            LOG_ERROR("load interpreter failed: %s", interpreter);
            return false;
        }
    }

    LOG_INFO("load program: %s", file.c_str());

    mProgramBase = loadSegments(reader);

    if (!mProgramBase)
        return false;

    mProgramEntry = reader.get_entry() + (reader.get_type() == ET_DYN ? mProgramBase : 0);
    mProgramHeader = mProgramBase + reader.get_segments_offset();
    mProgramHeaderNum = reader.segments.size();
    mProgramHeaderSize = reader.get_segment_entry_size();

    return true;
}

unsigned long ELFLoader::roundPage(unsigned long address) const {
    return (address + mPagesize - 1) & ~(mPagesize - 1);
}

unsigned long ELFLoader::truncatePage(unsigned long address) const {
    return address & ~(mPagesize - 1);
}

bool ELFLoader::loadInterpreter(const char *interpreter) {
    LOG_INFO("load interpreter: %s", interpreter);

    ELFIO::elfio reader;

    if (!reader.load(interpreter))
        return false;

    mInterpreterBase = loadSegments(reader);

    if (!mInterpreterBase)
        return false;

    mInterpreterEntry = reader.get_entry() + (reader.get_type() == ET_DYN ? mInterpreterBase : 0);

    return true;
}

unsigned long ELFLoader::loadSegments(const ELFIO::elfio &reader) {
    std::vector<ELFIO::segment *> loads;

    std::copy_if(
            reader.segments.begin(),
            reader.segments.end(),
            std::back_inserter(loads),
            [](const auto &i){
                return i->get_type() == PT_LOAD;
            });

    auto minElement = std::min_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            });

    auto maxElement = std::max_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            });

    bool dyn = reader.get_type() == ET_DYN;

    unsigned long minVA = truncatePage((*minElement)->get_virtual_address());
    unsigned long maxVA = roundPage((*maxElement)->get_virtual_address() + (*maxElement)->get_memory_size());

    void *base = mmap(
            dyn ? nullptr : (void *)minVA,
            maxVA - minVA,
            PROT_NONE,
            (dyn ? 0 : MAP_FIXED) | MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0);

    if (base == MAP_FAILED) {
        LOG_ERROR("mmap failed: %s", strerror(errno));
        return false;
    }

    munmap(base, maxVA - minVA);

    LOG_INFO("segment base: %p[0x%lx]", base, maxVA - minVA);

    for (const auto &segment : loads) {
        unsigned long offset = segment->get_virtual_address() & (mPagesize - 1);
        unsigned long start = (dyn ? (unsigned long)base : 0) + truncatePage(segment->get_virtual_address());
        unsigned long size = roundPage(segment->get_memory_size() + offset);

        LOG_INFO("segment: 0x%lx[0x%lx]", start, size);

        void *p = mmap(
                (void *)start,
                size,
                PROT_WRITE,
                MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0);

        if (p == MAP_FAILED) {
            LOG_ERROR("mmap failed: %s", strerror(errno));

            munmap(base, maxVA - minVA);
            return 0;
        }

        memcpy((unsigned char *)p + offset, segment->get_data(), segment->get_file_size());

        unsigned int flags = segment->get_flags();
        int protection = (flags & PF_R ? PROT_READ : 0) | (flags & PF_W ? PROT_WRITE : 0) | (flags & PF_X ? PROT_EXEC : 0);

        if (mprotect(p, size, protection) == -1) {
            LOG_ERROR("change memory protection failed: %s", strerror(errno));

            munmap(base, maxVA - minVA);
            return 0;
        }
    }

    return (unsigned long)base;
}

void ELFLoader::jump(int argc, char **argv, char **env) {
    std::ifstream stream = std::ifstream("/proc/self/auxv");
    std::vector<char> auxiliary((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

    for (auto *av = (Elf64_auxv_t *)auxiliary.data(); av->a_type != AT_NULL; av++) {
        switch (av->a_type) {
            case AT_PHDR:
                av->a_un.a_val = mProgramHeader;
                break;

            case AT_PHENT:
                av->a_un.a_val = mProgramHeaderSize;
                break;

            case AT_PHNUM:
                av->a_un.a_val = mProgramHeaderNum;
                break;

            case AT_BASE:
                av->a_un.a_val = mInterpreterBase ? mInterpreterBase : 0;
                break;

            case AT_ENTRY:
                av->a_un.a_val = mProgramEntry;
                break;

            case AT_EXECFN:
                av->a_un.a_val = (unsigned long)argv[0];
                break;
        }
    }

    unsigned char buffer[4096] = {};

    unsigned char *stack = buffer;
    unsigned long entry = mInterpreterEntry ? mInterpreterEntry : mProgramEntry;

    auto *p = (unsigned long *)stack;

    *(int *)p++ = argc;

    for (int i = 0; i < argc; i++)
        *(char **)p++ = argv[i];

    *(char **)p++ = nullptr;

    for (char ** i = env; *i; i++)
        *(char **)p++ = *i;

    *(char **)p++ = nullptr;

    memcpy(p, auxiliary.data(), auxiliary.size());

    asm volatile("mov %0, %%rsp; xor %%rdx, %%rdx; jmp *%1;" :: "m"(stack), "a"(entry));
}
