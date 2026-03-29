/*
 * Simplified ELF utility for Android
 */
#ifndef ELF_UTIL_H
#define ELF_UTIL_H

#include <string>
#include <link.h>
#include <stdint.h>

class ElfImg {
public:
    ElfImg(const char* elf_name);
    
    void* getSymbolAddress(const char* name);
    void* getSymbolAddressByPrefix(const char* prefix);
    bool isValid() const { return base != nullptr; }
    void* getBase() const { return base; }
    
private:
    void initModuleBase();
    void* findSymbol(const char* name);
    
    std::string elf;
    void* base = nullptr;
    off_t file_size = 0;
    
    void* dynsym = nullptr;
    void* strtab = nullptr;
    void* symtab = nullptr;
    size_t symtab_count = 0;
    
    uint32_t* gnu_hash = nullptr;
    uint32_t nbucket = 0;
    uint32_t* bucket = nullptr;
    uint32_t* chain = nullptr;
    
    void parseDynamic(void* file_mapped);
    uint32_t elfHash(const char* name) const;
    uint32_t gnuHash(const char* name) const;
};

#endif
