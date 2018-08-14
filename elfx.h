//
// Created by ulexec on 11/08/18.
//

#ifndef LIBX_ELFX_H
#define LIBX_ELFX_H

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <memory.h>
#include <zconf.h>
#include <stdlib.h>
#include <stdio.h>
#include "listx.h"

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

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)

/* We use this macro to refer to ELF macro constants.  For example,
   `ELFW(R_SYM)' is used in place of `ELF32_R_SYM' or `ELF64_R_SYM'.  */
#define ELFW(type)      _ElfW (ELF, __ELF_NATIVE_CLASS, type)

#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)  e##w##t
#define PtrW(type) _ElfW(type, __ELF_NATIVE_CLASS, t)

/* GNU header uses `JUMP_SLOT' while `JMP_SLOT' in FreeBSD. */
#define R_X86_64_JUMP_SLOT  R_X86_64_JMP_SLOT

#define PLTGOTLDENT 0x3
#define PLTENT 0x10
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)

#define bin_iter_phdrs(iter, bin) list_for_each(iter, &bin->phdrs.list)
#define bin_iter_phdrs_reverse(iter, bin) list_for_each_reverse(iter, &bin->phdrs.list)
#define bin_iter_shdrs(iter, bin) list_for_each(iter, &bin->shdrs.list)
#define bin_iter_shdrs_reverse(iter, bin) list_for_each_reverse(iter, &bin->shdrs.list)
#define bin_iter_dynamic(iter, bin) list_for_each(iter, &bin->dynamic.list)
#define bin_iter_dynamic_reverse(iter, bin) list_for_each_reverse(iter, &bin->dynamic.list)
#define bin_iter_symbols(iter, bin) list_for_each(iter, &bin->symbols.list)
#define bin_iter_symbols_reverse(iter, bin) list_for_each_reverse(iter, &bin->symbols.list)
#define bin_iter_dynamic_symbols(iter, bin) list_for_each(iter, &bin->dynamic_symbols.list)
#define bin_iter_dynamic_symbols_reverse(iter, bin) list_for_each_reverse(iter, &bin->dynamic_symbols.list)
#define bin_iter_relocs(iter, bin) list_for_each(iter, &bin->relocs.list)
#define bin_iter_relocs_reverse(iter, bin) list_for_each_reverse(iter, &bin->relocs.list)
#define bin_iter_gotplt(iter, bin) list_for_each(iter, &bin->pltgot.list)
#define bin_iter_gotplt_reverse(iter, bin) list_for_each_reverse(iter, &bin->pltgot.list)
#define bin_iter_plt(iter, bin) list_for_each(iter, &bin->plt.list)
#define bin_iter_plt_reverse(iter, bin) list_for_each_reverse(iter, &bin->plt.list)

typedef struct {
    struct list_head list;
    ElfW(Phdr) *data;
} Elfx_Phdr;

typedef struct {
    struct list_head list;
    ElfW(Shdr) *data;
} Elfx_Shdr;

typedef struct {
    struct list_head list;
    ElfW(Ehdr) *data;
} Elfx_Ehdr;

typedef struct {
    struct list_head list;
    ElfW(Rel) *data;
} Elfx_Rel;

typedef struct {
    struct list_head list;
    ElfW(Dyn) *data;
} Elfx_Dyn;

typedef struct {
    struct list_head list;
    ElfW(Sym) *data;
} Elfx_Sym;

typedef struct {
    struct list_head list;
    PtrW(uint) *data;
}Elfx_Ptr;

typedef struct {
    struct list_head list;
    PtrW(uint) *addr;
    uint8_t *bin_ptr;
}Elfx_Plt;

typedef struct {
    struct list_head list;
    ElfW(Ehdr) *ehdr;
    Elfx_Shdr shdrs;
    Elfx_Phdr phdrs;
    ElfW(Phdr) *code_phdr;
    ElfW(Phdr) *data_phdr;
    ElfW(Phdr) *dynamic_phdr;
    Elfx_Dyn dynamic;
    ElfW(Sym) *symtab;
    ElfW(Sym) *dynsym;
    Elfx_Sym symbols;
    Elfx_Sym dynamic_symbols;
    Elfx_Rel relocs;
    Elfx_Ptr pltgot;
    Elfx_Ptr got;
    Elfx_Ptr plt;
    ElfW(Rel) *rel;
    PtrW(uint) pltgot_addr;
    PtrW(uint) plt_addr;
    PtrW(uint) entry;
    PtrW(uint) image_base;
    uint8_t *data;
    uint8_t *path;
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
} Elfx_Bin;

Elfx_Bin * bin_load_elf(const char *, int, int);
void bin_save_elf(Elfx_Bin *);
uint8_t * get_section_name(Elfx_Bin *, ElfW(Shdr) *);
uint8_t * get_symbol_name(Elfx_Bin *, ElfW(Sym) *);
uint8_t * get_dynamic_symbol_name(Elfx_Bin *, ElfW(Sym) *);
Elfx_Ptr * get_got_entry_from_dynamic_symbol(Elfx_Bin *, char *);
int set_symbol_got_entry(Elfx_Bin *, uint8_t *, PtrW(uint));
void resolve_dynamic(Elfx_Bin *);
void resolve_symbols(Elfx_Bin *);
void resolve_dynamic_symbols(Elfx_Bin *);
void resolve_sections(Elfx_Bin *);
void resolve_segments(Elfx_Bin *);
void resolve_relocs(Elfx_Bin *);
void resolve_pltgot(Elfx_Bin *);
void resolve_plt(Elfx_Bin *bin);
int bin_unload_elf(Elfx_Bin *);
int segment_rva_to_offset_diff(Elfx_Bin *, Elfx_Phdr *);
int addr_to_offset(Elfx_Bin *, Elf64_Addr);
int addr_to_rva(Elfx_Bin *, uintptr_t);

#endif //LIBX_ELFX_H