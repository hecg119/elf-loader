#ifndef ELF_LOADER_LOADER_H
#define ELF_LOADER_LOADER_H

#include <string>
#include <elfio/elfio.hpp>

class ELFLoader {
public:
    ELFLoader();

public:
    bool load(const std::string& file);

public:
    void jump(int argc, char **argv);

private:
    bool loadInterpreter(const char *interpreter);

private:
    unsigned long loadSegments(const ELFIO::elfio &reader);

private:
    unsigned long roundPage(unsigned long address) const;
    unsigned long truncatePage(unsigned long address) const;

private:
    unsigned long mPagesize;

private:
    unsigned long mProgramBase{};
    unsigned long mProgramEntry{};
    unsigned long mProgramHeader{};
    unsigned long mProgramHeaderNum{};
    unsigned long mProgramHeaderSize{};

private:
    unsigned long mInterpreterBase{};
    unsigned long mInterpreterEntry{};
};


#endif //ELF_LOADER_LOADER_H
