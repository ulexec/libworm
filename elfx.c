//
// Created by ulexec on 12/08/18.
//

#include <elf.h>
#include "elfx.h"
#include "listx.h"

uint8_t * get_section_name(Elfx_Bin *bin, ElfW(Shdr) *shdr) {
    if (!bin->shstrtab) {
        return NULL;
    }
    return &bin->shstrtab[shdr->sh_name];
}

uint8_t * get_symbol_name(Elfx_Bin *bin, ElfW(Sym) *sym) {
    if (!bin->strtab) {
        return NULL;
    }
    return &bin->strtab[sym->st_name];
}

uint8_t * get_dynamic_symbol_name(Elfx_Bin *bin, ElfW(Sym) *sym) {
    if (!bin->dynstr) {
        return NULL;
    }
    return &bin->dynstr[sym->st_name];
}

int bin_unload_elf(Elfx_Bin *bin) {
    struct list_head *iter;

    BIN_ITER_SHDRS_REVERSE(iter, bin) {
        Elfx_Shdr *shdr = GET_LIST_ENTRY (iter, Elfx_Shdr);
        list_del (&shdr->list);
        free (shdr);
    }
    BIN_ITER_PHDRS_REVERSE(iter, bin) {
        Elfx_Phdr *phdr = GET_LIST_ENTRY (iter, Elfx_Phdr);
        list_del (&phdr->list);
        free (phdr);
    }
    BIN_ITER_SYMBOLS_REVERSE(iter, bin) {
        Elfx_Sym *sym = GET_LIST_ENTRY (iter, Elfx_Sym);
        list_del (&sym->list);
        free (sym);
    }
    BIN_ITER_DYNAMIC_SYMBOLS_REVERSE(iter, bin) {
        Elfx_Sym *sym = GET_LIST_ENTRY (iter, Elfx_Sym);
        list_del (&sym->list);
        free (sym);
    }
    BIN_ITER_DYNAMIC_REVERSE(iter, bin) {
        Elfx_Dyn *dyn = GET_LIST_ENTRY (iter, Elfx_Dyn);
        list_del (&dyn->list);
        free (dyn);
    }
    BIN_ITER_RELOCS_REVERSE(iter, bin) {
        Elfx_Rel *rel = GET_LIST_ENTRY (iter, Elfx_Rel);
        list_del (&rel->list);
        free (rel);
    }
    BIN_ITER_GOTPLT_REVERSE(iter, bin) {
        Elfx_Ptr *ptr = GET_LIST_ENTRY (iter, Elfx_Ptr);
        list_del (&ptr->list);
        free (ptr);
    }
    BIN_ITER_PLT_REVERSE(iter, bin) {
        Elfx_Plt *plt = GET_LIST_ENTRY(iter, Elfx_Plt);
        list_del(&plt->list);
        free(plt);
    }
    close (bin->fd);
    free (bin);
    return 0;
}

void bin_save_elf(Elfx_Bin *bin) {
    write(bin->fd, bin->data, (size_t) bin->size);
}

void resolve_symbols(Elfx_Bin *bin) {

    init_list_head (&bin->symbols.list);
    for (int i = 0; i < bin->sym_num; i++) {
        Elfx_Sym *sym_entry = (Elfx_Sym *)calloc (1, sizeof(Elfx_Sym));
        sym_entry->data = &bin->symtab[i];
        list_add_tail (&sym_entry->list, &bin->symbols.list);
    }
}

void resolve_sections(Elfx_Bin *bin) {
    ElfW(Shdr) *shdr;

    shdr = (ElfW(Shdr) *)(bin->data + bin->ehdr->e_shoff);
    bin->shstrtab = &bin->data[shdr[bin->ehdr->e_shstrndx].sh_offset];

    init_list_head (&bin->shdrs.list);
    for (int i = 0; i < bin->ehdr->e_shnum; i++) {
        Elfx_Shdr *shdr_entry = (Elfx_Shdr *)calloc (1, sizeof(Elfx_Shdr));
        shdr_entry->data = &shdr[i];

        list_add_tail (&shdr_entry->list, &bin->shdrs.list);
        switch (shdr[i].sh_type) {
            case SHT_SYMTAB:
                if (!strcmp ((const char *)get_section_name (bin, shdr_entry->data), ".symtab")) {
                    bin->symtab = (ElfW(Sym) *)&bin->data[shdr_entry->data->sh_offset];
                    bin->sym_num = (int)(shdr_entry->data->sh_size / sizeof (ElfW(Sym)));
                    ElfW(Shdr) *strtab_shdr = &shdr[shdr_entry->data->sh_link];
                    bin->strtab = &bin->data[strtab_shdr->sh_offset];
                }
                break;
            default:
                break;
        }
    }
}

void resolve_segments(Elfx_Bin *bin) {
    ElfW(Phdr) *phdr;

    phdr = (ElfW(Phdr) *)(bin->data + bin->ehdr->e_phoff);
    init_list_head (&bin->phdrs.list);

    for (int i = 0; i < bin->ehdr->e_phnum; i++) {
        Elfx_Phdr *phdr_entry = (Elfx_Phdr *)calloc (1, sizeof(Elfx_Phdr));
        phdr_entry->data = &phdr[i];

        list_add_tail (&phdr_entry->list, &bin->phdrs.list);

        switch (phdr[i].p_type) {
            case PT_LOAD:
                if (!phdr[i].p_offset) {
                    bin->code_phdr = &phdr[i];
                    bin->image_base = (uint32_t)phdr[i].p_vaddr;
                } else {
                    bin->data_phdr = &phdr[i];
                }
                break;
            case PT_DYNAMIC:
                bin->dynamic_phdr = &phdr[i];
                bin->dynamic_num = (int)phdr[i].p_filesz / sizeof (Elfx_Sym);
                break;
            default:
                break;
        }
    }
}

int addr_to_rva(Elfx_Bin *bin, uintptr_t addr) {
    return (int)(addr - bin->image_base);
}

int rva_to_addr(Elfx_Bin *bin, int rva) {
    return (int)(rva + bin->image_base);
}

int segment_rva_to_offset_diff(Elfx_Bin *bin, Elfx_Phdr *phdr) {
    return (int)(phdr->data->p_offset - addr_to_rva (bin, phdr->data->p_vaddr));
}

int addr_to_offset(Elfx_Bin *bin, uintptr_t addr) {
    struct list_head *iter;

    BIN_ITER_PHDRS (iter, bin) {
        Elfx_Phdr *phdr = GET_LIST_ENTRY(iter, Elfx_Phdr);
        if(phdr->data->p_type == PT_LOAD) {
            if ((uintptr_t) phdr->data->p_vaddr <= addr && addr <= phdr->data->p_vaddr + phdr->data->p_filesz) {
                return (addr_to_rva(bin, addr) + segment_rva_to_offset_diff(bin, phdr));
            }
        }
    }
    return 0;
}

int offset_to_addr(Elfx_Bin *bin, int offset) {
    struct list_head *iter;

    BIN_ITER_PHDRS (iter, bin) {
        Elfx_Phdr *phdr = GET_LIST_ENTRY(iter, Elfx_Phdr);
        if(phdr->data->p_type == PT_LOAD) {
            if(phdr->data->p_offset <= offset && offset <= phdr->data->p_offset + phdr->data->p_filesz) {
                return (offset + (phdr->data->p_vaddr - phdr->data->p_offset));
            }
        }
    }
    return 0;
}

void resolve_dynamic_symbols(Elfx_Bin *bin) {

    init_list_head (&bin->dynamic_symbols.list);

    for (int i = 0; i < bin->pltgot_num; i++) {
        Elfx_Sym *sym = (Elfx_Sym *)calloc (1, sizeof(Elfx_Sym));
        sym->data = &bin->dynsym[i];
        list_add_tail (&sym->list, &bin->dynamic_symbols.list);
    }
}

void resolve_dynamic(Elfx_Bin *bin) {
    ElfW(Dyn) *dynamic, *entry;

    dynamic = (ElfW(Dyn) *)&bin->data[bin->dynamic_phdr->p_offset];
    bin->rel_num = 0;

    init_list_head (&bin->dynamic.list);
    for (int i = 0; ; i++) {
        Elfx_Dyn *dyn_node = (Elfx_Dyn *)calloc (1, sizeof (Elfx_Dyn));
        entry = &dynamic[i];
        dyn_node->data = entry;

        list_add_tail (&dyn_node->list, &bin->dynamic.list);

        switch (entry->d_tag) {
            case DT_SYMTAB:
                bin->dynsym = (ElfW(Sym *))&bin->data[addr_to_offset (bin, (uintptr_t)entry->d_un.d_ptr)];
                break;
            case DT_STRTAB:
                bin->dynstr = &bin->data[addr_to_offset (bin, (uintptr_t)entry->d_un.d_ptr)];
                break;
            case DT_STRSZ:
                bin->dynsym_num = (int)entry->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELA:
                bin->rel = (ElfW(Rel) *)&bin->data[addr_to_offset (bin, (uintptr_t)entry->d_un.d_ptr)];
                break;
            case DT_RELSZ:
            case DT_RELASZ:
                bin->relocs_num += (int)entry->d_un.d_val;
                bin->rel_num = (int)entry->d_un.d_val;
                break;
            case DT_PLTRELSZ:
                bin->relocs_num += (int)entry->d_un.d_val;
                bin->pltgot_num = (int)entry->d_un.d_val;
                break;
            case DT_RELENT:
            case DT_RELAENT:
                bin->rel_num /= (int)entry->d_un.d_val;
                bin->relocs_num /= (int)entry->d_un.d_val;
                bin->pltgot_num /= (int)entry->d_un.d_val;
                break;
            case DT_PLTGOT:
                bin->pltgot_addr = (int)entry->d_un.d_ptr;
                break;
            case DT_NULL:
                return;
            default:
                break;
        }
    }
}

void resolve_pltgot(Elfx_Bin *bin) {
    PtrW(uint) *got_data = (PtrW(uint) *)&bin->data[addr_to_offset(bin, bin->pltgot_addr)];

    init_list_head(&bin->pltgot.list);

    for (int i = 0; i < bin->pltgot_num + PLTGOTLDENT; i++) {
        Elfx_Ptr *ptr = (Elfx_Ptr *)calloc (1, sizeof(Elfx_Ptr));
        ptr->data = &got_data[i];
        list_add_tail(&ptr->list, &bin->pltgot.list);
    }
}

void resolve_plt(Elfx_Bin *bin) {
    uint8_t *plt_entry;
    Elfx_Ptr *got_entry;
    struct list_head *iter;
    int i = 0;

    BIN_ITER_GOTPLT(iter, bin) {
        got_entry = GET_LIST_ENTRY(iter, Elfx_Ptr);
        if (i++ == PLTGOTLDENT) {
            bin->plt_addr = ((*got_entry->data >> 4) << 4) - 0x10;
            break;
        }
    }
    plt_entry = &bin->data[addr_to_offset(bin, bin->plt_addr)];

    init_list_head(&bin->plt.list);
    for (i = 0; i <= bin->pltgot_num; i++) {
        Elfx_Plt *plt = (Elfx_Plt *)calloc (1, sizeof(Elfx_Plt));
        plt->bin_ptr = ((uint8_t *)plt_entry + i * PLTENT);
        plt->addr = (PtrW(uint) *)((uint8_t *)bin->plt_addr + i * PLTENT);
        list_add_tail(&plt->list, &bin->plt.list);
    }
}

void resolve_relocs(Elfx_Bin *bin) {

    init_list_head(&bin->relocs.list);

    for (int i = 0; i < bin->relocs_num; i++) {
        Elfx_Rel *entry = (Elfx_Rel *) calloc(1, sizeof(Elfx_Rel));
        entry->data = &bin->rel[i];
        list_add_tail(&entry->list, &bin->relocs.list);
    }
}

Elfx_Ptr * get_got_entry_from_dynamic_symbol(Elfx_Bin *bin, char *sym_name) {
    struct list_head *iter;
    Elfx_Rel *rel;
    uint8_t *dyn_name;
    ElfW(Sym) *sym;
    int sym_index=0, offset=0, i;

    BIN_ITER_RELOCS(iter, bin) {
        rel = GET_LIST_ENTRY(iter, Elfx_Rel);
        sym_index = __ELF_NATIVE_CLASS == 64 ? ELF64_R_SYM(rel->data->r_info) :  ELF32_R_SYM(rel->data->r_info);
        sym = &bin->dynsym[sym_index];
        dyn_name = get_dynamic_symbol_name(bin, sym);
        if (!(strlen(dyn_name) - strlen(sym_name)) && !strncmp(dyn_name, sym_name, strlen(sym_name))) {
            break;
        }
        offset++;
    }
    offset -= bin->rel_num;

    i = 0;
    BIN_ITER_GOTPLT(iter, bin) {
        if (i++ == offset + PLTGOTLDENT) {
            return GET_LIST_ENTRY(iter, Elfx_Ptr);
        }
    }
    return NULL;
}

int set_symbol_got_entry(Elfx_Bin *bin, uint8_t *sym_name, PtrW(uint) value) {
    Elfx_Ptr *got_ent;
    if(!(got_ent = get_got_entry_from_dynamic_symbol(bin, sym_name))) {
        return -1;
    }
    *(PtrW(uint) *)got_ent->data = value;
    return 0;
}

Elfx_Bin * bin_load_elf(const char *path, int prot, int flags) {
    int fd;
    struct stat st;
    Elfx_Bin *bin;

    bin = (Elfx_Bin*)calloc (1, sizeof(Elfx_Bin));
    if (!bin) {
        perror ("calloc");
        return NULL;
    }
    if ((bin->fd = open (path, O_RDWR)) < 0) {
        perror ("open");
        return NULL;
    }
    if (fstat (bin->fd, &st) < 0) {
        perror ("fstat");
        return NULL;
    }

    bin->data = mmap (NULL, (size_t)PAGE_ALIGN_UP (st.st_size), prot, flags, bin->fd, 0);
    if (bin->data == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    bin->path = (uint8_t *) strdup(path);
    bin->size = (int) st.st_size;
    bin->ehdr = (ElfW(Ehdr) *)bin->data;
    bin->type = bin->ehdr->e_type;
    bin->entry = bin->ehdr->e_entry;

    resolve_sections (bin);
    resolve_segments (bin);
    resolve_dynamic (bin);
    resolve_symbols (bin);
    resolve_dynamic_symbols (bin);
    resolve_relocs (bin);
    resolve_pltgot (bin);
    resolve_plt (bin);
    return bin;
}