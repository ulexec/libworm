//
// Created by ulexec on 11/08/18.
//

#ifndef LIBWORM_ELFX_H
#define LIBWORM_ELFX_H

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <memory.h>
#include <zconf.h>
#include <stdlib.h>
#include <stdio.h>
#include "listw.h"

#ifndef __ELF_NATIVE_CLASS
#  if defined(_M_X64) || defined(__x86_64) || defined(__amd64)
#    include <limits.h>     /* for UINT_MAX */
#    define __ELF_NATIVE_CLASS 64
#  else
#    define __ELF_NATIVE_CLASS 32
#  endif
#endif

#if __ELF_NATIVE_CLASS == 64
#    define Rel Rela
#endif

#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)  e##w##t
#define PtrW(type) _ElfW(type, __ELF_NATIVE_CLASS, t)

#define PLTGOTLDENT 0x3
#define PLTENT 0x10
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)

#define BIN_ITER_PHDRS(iter, bin) LIST_FOR_EACH(iter, &bin->phdrs.list)
#define BIN_ITER_PHDRS_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->phdrs.list)
#define BIN_ITER_SHDRS(iter, bin) LIST_FOR_EACH(iter, &bin->shdrs.list)
#define BIN_ITER_SHDRS_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->shdrs.list)
#define BIN_ITER_DYNAMIC(iter, bin) LIST_FOR_EACH(iter, &bin->dynamic.list)
#define BIN_ITER_DYNAMIC_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->dynamic.list)
#define BIN_ITER_SYMBOLS(iter, bin) LIST_FOR_EACH(iter, &bin->symbols.list)
#define BIN_ITER_SYMBOLS_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->symbols.list)
#define BIN_ITER_DYNAMIC_SYMBOLS(iter, bin) LIST_FOR_EACH(iter, &bin->dynamic_symbols.list)
#define BIN_ITER_DYNAMIC_SYMBOLS_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->dynamic_symbols.list)
#define BIN_ITER_RELOCS(iter, bin) LIST_FOR_EACH(iter, &bin->relocs.list)
#define BIN_ITER_RELOCS_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->relocs.list)
#define BIN_ITER_GOTPLT(iter, bin) LIST_FOR_EACH(iter, &bin->pltgot.list)
#define BIN_ITER_GOTPLT_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->pltgot.list)
#define BIN_ITER_PLT(iter, bin) LIST_FOR_EACH(iter, &bin->plt.list)
#define BIN_ITER_PLT_REVERSE(iter, bin) LIST_FOR_EACH_REVERSE(iter, &bin->plt.list)

typedef struct {
    struct list_head list;
    ElfW(Phdr) *data;
} Elfw_Phdr;

typedef struct {
    struct list_head list;
    ElfW(Shdr) *data;
} Elfw_Shdr;

typedef struct {
    struct list_head list;
    ElfW(Ehdr) *data;
} Elfw_Ehdr;

typedef struct {
    struct list_head list;
    ElfW(Rel) *data;
} Elfw_Rel;

typedef struct {
    struct list_head list;
    ElfW(Dyn) *data;
} Elfw_Dyn;

typedef struct {
    struct list_head list;
    ElfW(Sym) *data;
} Elfw_Sym;

typedef struct {
    struct list_head list;
    PtrW(uint) *data;
}Elfw_Ptr;

typedef struct {
    struct list_head list;
    PtrW(uint) *addr;
}Elfw_Plt;

typedef struct {
    struct list_head list;
    ElfW(Ehdr) *ehdr;
    Elfw_Shdr shdrs;
    Elfw_Phdr phdrs;
    ElfW(Phdr) *code_phdr;
    ElfW(Phdr) *data_phdr;
    ElfW(Phdr) *dynamic_phdr;
    Elfw_Dyn dynamic;
    ElfW(Sym) *symtab;
    ElfW(Sym) *dynsym;
    Elfw_Sym symbols;
    Elfw_Sym dynamic_symbols;
    Elfw_Rel relocs;
    Elfw_Ptr pltgot;
    Elfw_Ptr got;
    Elfw_Ptr plt;
    ElfW(Rel) *rel;
    PtrW(uint) pltgot_addr;
    PtrW(uint) plt_addr;
    PtrW(uint) entry;
    PtrW(uint) image_base;
    uint8_t *data;
    const char *path;
    uint8_t *shstrtab;
    uint8_t *strtab;
    uint8_t *dynstr;
    int fd;
    int size;
    int type;
    int sym_num;
    int dynamic_num;
    int dynsym_num;
    int relocs_num;
    int rel_num;
    int pltgot_num;
} Elfw_Bin;

typedef struct {
    size_t size;
    uint8_t *code;
}Elfw_Code;

int bin_load_elf(Elfw_Bin **, const char *, int, int);
int bin_elf_new(Elfw_Bin **, const char *, int);
int bin_update_elf(Elfw_Bin *, int, int);
int get_section_name(Elfw_Bin *, ElfW(Shdr) *, char **);
int get_symbol_name(Elfw_Bin *, ElfW(Sym) *, char **);
int get_dynamic_symbol_name(Elfw_Bin *, ElfW(Sym) *, char **);
int get_got_entry_from_dynamic_symbol(Elfw_Bin *, Elfw_Ptr **, char *);
int set_symbol_got_entry(Elfw_Bin *, char *, PtrW(uint));
void resolve_dynamic(Elfw_Bin *);
void resolve_symbols(Elfw_Bin *);
void resolve_dynamic_symbols(Elfw_Bin *);
void resolve_sections(Elfw_Bin *);
void resolve_segments(Elfw_Bin *);
void resolve_relocs(Elfw_Bin *);
int resolve_pltgot(Elfw_Bin *);
int resolve_plt(Elfw_Bin *bin);
void bin_unload_elf(Elfw_Bin *);
int segment_rva_to_offset_delta(Elfw_Bin *, Elfw_Phdr *);
int addr_to_offset(Elfw_Bin *, int, int*);
int offset_to_addr(Elfw_Bin *, int, int*);
int addr_to_rva(Elfw_Bin *, uintptr_t);
int rva_to_addr(Elfw_Bin *, int);


#endif //LIBWORM_ELFX_H