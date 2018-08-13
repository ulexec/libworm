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
#    define RTS_DT_REL    DT_RELA
#    define RTS_DT_RELSZ  DT_RELASZ
#    define RTS_DT_RELENT DT_RELAENT
#else
#    define RTS_DT_REL    DT_REL
#    define RTS_DT_RELSZ  DT_RELSZ
#    define RTS_DT_RELENT DT_RELENT
#endif

/* We use this macro to refer to ELF types independent of the native wordsize.
   `ElfW(TYPE)' is used in place of `Elf32_TYPE' or `Elf64_TYPE'.  */
#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)

/* We use this macro to refer to ELF macro constants.  For example,
   `ELFW(R_SYM)' is used in place of `ELF32_R_SYM' or `ELF64_R_SYM'.  */
#define ELFW(type)      _ElfW (ELF, __ELF_NATIVE_CLASS, type)

#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)  e##w##t

/* GNU header uses `JUMP_SLOT' while `JMP_SLOT' in FreeBSD. */
#define R_X86_64_JUMP_SLOT  R_X86_64_JMP_SLOT

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
    Elfx_Rel *rel;
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
    uintptr_t entry;
    uintptr_t image_base;
} Elfx_Bin;

Elfx_Bin * bin_load_elf(const char *, int, int);
uint8_t * get_section_name(Elfx_Bin *, Elfx_Shdr *);
uint8_t * get_symbol_name(Elfx_Bin *, Elfx_Sym *);
uint8_t * get_dynamic_symbol_name(Elfx_Bin *, Elfx_Sym *);
void resolve_dynamic(Elfx_Bin *);
void resolve_symbols(Elfx_Bin *);
void resolve_dynamic_symbols(Elfx_Bin *);
void resolve_sections(Elfx_Bin *);
void resolve_segments(Elfx_Bin *);
int bin_unload_elf(Elfx_Bin *);
int segment_rva_to_offset_diff(Elfx_Bin *, Elfx_Phdr *);
int addr_to_offset(Elfx_Bin *, Elf64_Addr);
int addr_to_rva(Elfx_Bin *, uintptr_t);

#endif //LIBX_ELFX_H