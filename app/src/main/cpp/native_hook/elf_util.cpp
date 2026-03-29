/*
 * Simplified ELF utility implementation for Android
 * Fixed: Use mmap'd file for parsing, correct dynamic address, no bias needed
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <android/log.h>

#include "elf_util.h"

#define LOG_TAG "ElfUtil"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

ElfImg::ElfImg(const char* elf_name) : elf(elf_name) {
    initModuleBase();
    if (!base) return;
    
    ALOGI("ElfImg: base=%p", base);
    
    int fd = open(elf.c_str(), O_RDONLY);
    if (fd < 0) {
        ALOGE("Failed to open %s", elf.c_str());
        return;
    }
    
    file_size = lseek(fd, 0, SEEK_END);
    if (file_size <= 0) {
        ALOGE("lseek() failed for %s", elf.c_str());
        close(fd);
        return;
    }
    
    // Bug 3 fix: mmap the file and use it for parsing
    void* file_mapped = mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    
    if (file_mapped == MAP_FAILED) {
        ALOGE("mmap failed");
        return;
    }
    
    // Parse the ELF file (not process memory)
    parseDynamic(file_mapped);
    
    munmap(file_mapped, file_size);
}

void ElfImg::initModuleBase() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, elf.c_str())) {
            uint64_t start;
            sscanf(line, "%lx-", &start);
            base = (void*)start;
            ALOGI("Found %s at base=%p", elf.c_str(), base);
            break;
        }
    }
    fclose(fp);
}

void ElfImg::parseDynamic(void* file_mapped) {
    // Bug 3 fix: Parse the mmap'd file, not process memory
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_mapped;
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)file_mapped + ehdr->e_phoff);
    
    ALOGI("parseDynamic: e_phnum=%d", ehdr->e_phnum);
    
    uint64_t dynamic_vaddr = 0;
    
    // Bug 1 fix: Find PT_DYNAMIC and use its p_vaddr
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic_vaddr = phdr[i].p_vaddr;
            ALOGI("Found PT_DYNAMIC at p_vaddr=0x%lx, p_offset=0x%lx", 
                  phdr[i].p_vaddr, phdr[i].p_offset);
            break;
        }
    }
    
    if (!dynamic_vaddr) {
        ALOGE("No PT_DYNAMIC found!");
        return;
    }
    
    // Calculate load bias (p_vaddr - p_offset for first PT_LOAD)
    uint64_t load_bias = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            load_bias = phdr[i].p_vaddr - phdr[i].p_offset;
            ALOGI("First PT_LOAD: p_vaddr=0x%lx, p_offset=0x%lx, load_bias=0x%lx",
                  phdr[i].p_vaddr, phdr[i].p_offset, load_bias);
            break;
        }
    }
    
    // Correct dynamic address: file address + base - load_bias
    // Bug 1 fix: Use p_vaddr from PT_DYNAMIC, not hardcoded 0x1000
    uint64_t dynamic_file_offset = dynamic_vaddr - load_bias;
    Elf64_Dyn* dynamic = (Elf64_Dyn*)((char*)file_mapped + dynamic_file_offset);
    
    ALOGI("Dynamic: file_offset=0x%lx, computed addr=%p", 
          dynamic_file_offset, dynamic);
    
    // Scan dynamic section (in file)
    int dyn_count = 0;
    for (int i = 0; i < 200 && dynamic[i].d_tag != DT_NULL; i++) {
        dyn_count++;
        
        if (dynamic[i].d_tag == DT_STRTAB) {
            uint64_t val = dynamic[i].d_un.d_val;
            strtab = (void*)((char*)file_mapped + (val - load_bias));
            ALOGI("Found DT_STRTAB: d_val=0x%lx, addr=%p", val, strtab);
        } else if (dynamic[i].d_tag == DT_SYMTAB) {
            uint64_t val = dynamic[i].d_un.d_val;
            dynsym = (void*)((char*)file_mapped + (val - load_bias));
            ALOGI("Found DT_SYMTAB: d_val=0x%lx, addr=%p", val, dynsym);
        } else if (dynamic[i].d_tag == DT_GNU_HASH) {
            uint64_t val = dynamic[i].d_un.d_val;
            gnu_hash = (uint32_t*)((char*)file_mapped + (val - load_bias));
            ALOGI("Found DT_GNU_HASH: d_val=0x%lx, addr=%p", val, gnu_hash);
            if (gnu_hash) {
                nbucket = gnu_hash[0];
                bucket = &gnu_hash[4 + (gnu_hash[2] / sizeof(void*))];
                chain = &bucket[nbucket];
                ALOGI("GNU_HASH: nbucket=%d", nbucket);
            }
        } else if (dynamic[i].d_tag == DT_HASH) {
            uint64_t val = dynamic[i].d_un.d_val;
            uint32_t* h = (uint32_t*)((char*)file_mapped + (val - load_bias));
            ALOGI("Found DT_HASH: d_val=0x%lx, addr=%p", val, h);
            nbucket = h[0];
            symtab_count = h[1];
            bucket = &h[2];
            chain = &bucket[nbucket];
            ALOGI("ELF_HASH: nbucket=%d, symtab_count=%zu", nbucket, symtab_count);
        }
    }
    
    ALOGI("Scanned %d dynamic entries", dyn_count);
    
    if (!dynsym || !strtab) {
        ALOGE("Missing dynsym or strtab! dynsym=%p strtab=%p", dynsym, strtab);
    }
}

uint32_t ElfImg::elfHash(const char* name) const {
    uint32_t h = 0;
    while (*name) {
        h = (h << 4) + *name++;
        uint32_t g = h & 0xf0000000;
        h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

uint32_t ElfImg::gnuHash(const char* name) const {
    uint32_t h = 5381;
    while (*name) {
        h += (h << 5) + *name++;
    }
    return h;
}

void* ElfImg::findSymbol(const char* name) {
    if (!dynsym || !strtab || !base) {
        ALOGE("findSymbol: dynsym=%p strtab=%p base=%p", dynsym, strtab, base);
        return nullptr;
    }
    
    if (gnu_hash) {
        uint32_t h = gnuHash(name);
        uint32_t idx = bucket[h % nbucket];
        
        ALOGI("Searching for %s, hash=0x%x, idx=%d", name, h, idx);
        
        int attempts = 0;
        while (idx != 0 && attempts < 100) {
            Elf64_Sym* sym = ((Elf64_Sym*)dynsym) + idx;
            char* sym_name = (char*)strtab + sym->st_name;
            if (strcmp(sym_name, name) == 0) {
                // Bug 2 fix: Just use base + st_value (no bias)
                void* addr = (void*)((char*)base + sym->st_value);
                ALOGI("Found %s at %p (st_value=0x%lx)", name, addr, sym->st_value);
                return addr;
            }
            idx = chain[idx];
            attempts++;
        }
    }
    
    return nullptr;
}

void* ElfImg::getSymbolAddress(const char* name) {
    return findSymbol(name);
}

void* ElfImg::getSymbolAddressByPrefix(const char* prefix) {
    if (!dynsym || !strtab || !base) {
        ALOGE("getSymbolAddressByPrefix: dynsym=%p strtab=%p base=%p", 
              dynsym, strtab, base);
        return nullptr;
    }
    
    size_t prefix_len = strlen(prefix);
    
    ALOGI("Prefix searching for: %s", prefix);
    
    // Iterate through symbol table - note: dynsym points to file memory
    for (uint32_t i = 1; i < 10000; i++) {
        Elf64_Sym* sym = ((Elf64_Sym*)dynsym) + i;
        if (sym->st_name == 0) continue;
        if (sym->st_value == 0) continue;
        
        char* sym_name = (char*)strtab + sym->st_name;
        if (sym_name && strncmp(sym_name, prefix, prefix_len) == 0) {
            // Bug 2 fix: Just use base + st_value (no bias)
            void* addr = (void*)((char*)base + sym->st_value);
            uintptr_t addr_val = (uintptr_t)addr;
            uintptr_t base_val = (uintptr_t)base;
            
            ALOGI("Found prefix match: %s at %p (st_value=0x%lx, base=%p)", 
                  sym_name, addr, sym->st_value, base);
            
            if (addr_val >= base_val && addr_val <= base_val + 0x200000) {
                return addr;
            }
        }
    }
    
    ALOGI("Prefix %s not found", prefix);
    return nullptr;
}
