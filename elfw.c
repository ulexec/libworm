//
// Created by ulexec on 12/08/18.
//

#include "worm.h"

int get_section_name(Elfw_Bin *bin, ElfW(Shdr) *shdr, char **section_name) {
    if (!bin->shstrtab) {
        return LIBWORM_ERROR;
    }
    *section_name = &bin->shstrtab[shdr->sh_name];
    return LIBWORM_SUCCESS;
}

int get_symbol_name(Elfw_Bin *bin, ElfW(Sym) *sym, char **symbol_name) {
    if (!bin->strtab) {
        return LIBWORM_ERROR;
    }
    *symbol_name = &bin->strtab[sym->st_name];
    return LIBWORM_SUCCESS;
}

int get_dynamic_symbol_name(Elfw_Bin *bin, ElfW(Sym) *sym, char **symbol_name) {
    if (!bin->dynstr) {
        return LIBWORM_ERROR;
    }
    *symbol_name = &bin->dynstr[sym->st_name];
    return LIBWORM_SUCCESS;
}

void bin_unload_elf(Elfw_Bin *bin) {
    struct list_head *iter;

    BIN_ITER_SHDRS_REVERSE(iter, bin) {
        Elfw_Shdr *shdr = GET_LIST_ENTRY (iter, Elfw_Shdr);
        list_del (&shdr->list);
        free (shdr);
    }
    BIN_ITER_PHDRS_REVERSE(iter, bin) {
        Elfw_Phdr *phdr = GET_LIST_ENTRY (iter, Elfw_Phdr);
        list_del (&phdr->list);
        free (phdr);
    }
    BIN_ITER_SYMBOLS_REVERSE(iter, bin) {
        Elfw_Sym *sym = GET_LIST_ENTRY (iter, Elfw_Sym);
        list_del (&sym->list);
        free (sym);
    }
    BIN_ITER_DYNAMIC_SYMBOLS_REVERSE(iter, bin) {
        Elfw_Sym *sym = GET_LIST_ENTRY (iter, Elfw_Sym);
        list_del (&sym->list);
        free (sym);
    }
    BIN_ITER_DYNAMIC_REVERSE(iter, bin) {
        Elfw_Dyn *dyn = GET_LIST_ENTRY (iter, Elfw_Dyn);
        list_del (&dyn->list);
        free (dyn);
    }
    BIN_ITER_RELOCS_REVERSE(iter, bin) {
        Elfw_Rel *rel = GET_LIST_ENTRY (iter, Elfw_Rel);
        list_del (&rel->list);
        free (rel);
    }
    BIN_ITER_GOTPLT_REVERSE(iter, bin) {
        Elfw_Ptr *ptr = GET_LIST_ENTRY (iter, Elfw_Ptr);
        list_del (&ptr->list);
        free (ptr);
    }
    BIN_ITER_PLT_REVERSE(iter, bin) {
        Elfw_Plt *plt = GET_LIST_ENTRY(iter, Elfw_Plt);
        list_del(&plt->list);
        free(plt);
    }
    close (bin->fd);
    free (bin);
}

int bin_update_elf(Elfw_Bin *bin, int size, int offset) {
    if (pwrite(bin->fd, bin->data, (size_t) size, offset) != size) {
        perror("write");
        return LIBWORM_ERROR;
    }
    return LIBWORM_SUCCESS;
}

void resolve_symbols(Elfw_Bin *bin) {
    init_list_head (&bin->symbols.list);
    for (int i = 0; i < bin->sym_num; i++) {
        Elfw_Sym *sym_entry = (Elfw_Sym *)calloc (1, sizeof(Elfw_Sym));
        sym_entry->data = &bin->symtab[i];
        list_add_tail (&sym_entry->list, &bin->symbols.list);
    }
}

void resolve_sections(Elfw_Bin *bin) {
    ElfW(Shdr) *shdr;
    char *section_name;

    shdr = (ElfW(Shdr) *)&bin->data[bin->ehdr->e_shoff];
    bin->shstrtab = &bin->data[shdr[bin->ehdr->e_shstrndx].sh_offset];

    init_list_head (&bin->shdrs.list);
    for (int i = 0; i < bin->ehdr->e_shnum; i++) {
        Elfw_Shdr *shdr_entry = (Elfw_Shdr *)calloc (1, sizeof(Elfw_Shdr));
        shdr_entry->data = &shdr[i];

        list_add_tail (&shdr_entry->list, &bin->shdrs.list);
        switch (shdr[i].sh_type) {
            case SHT_SYMTAB:
                if(get_section_name(bin, shdr_entry->data, &section_name) == LIBWORM_SUCCESS) {
                    if (!strcmp (section_name, ".symtab")) {
                        bin->symtab = (ElfW(Sym) *)&bin->data[shdr_entry->data->sh_offset];
                        bin->sym_num = (int)(shdr_entry->data->sh_size / sizeof (ElfW(Sym)));
                        ElfW(Shdr) *strtab_shdr = &shdr[shdr_entry->data->sh_link];
                        bin->strtab = &bin->data[strtab_shdr->sh_offset];
                    }
                }
                break;
            default:
                break;
        }
    }
}

void resolve_segments(Elfw_Bin *bin) {
    ElfW(Phdr) *phdr;

    phdr = (ElfW(Phdr) *)(bin->data + bin->ehdr->e_phoff);
    init_list_head (&bin->phdrs.list);

    for (int i = 0; i < bin->ehdr->e_phnum; i++) {
        Elfw_Phdr *phdr_entry = (Elfw_Phdr *)calloc (1, sizeof(Elfw_Phdr));
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
                bin->dynamic_num = (int)phdr[i].p_filesz / sizeof (Elfw_Sym);
                break;
            default:
                break;
        }
    }
}

int addr_to_rva(Elfw_Bin *bin, uintptr_t addr) {
    return (int)(addr - bin->image_base);
}

int rva_to_addr(Elfw_Bin *bin, int rva) {
    return (int)(rva + bin->image_base);
}

int segment_rva_to_offset_delta(Elfw_Bin *bin, Elfw_Phdr *phdr) {
    return (int)(phdr->data->p_offset - addr_to_rva (bin, phdr->data->p_vaddr));
}

int addr_to_offset(Elfw_Bin *bin, int addr, int *output) {
    struct list_head *iter;

    BIN_ITER_PHDRS (iter, bin) {
        Elfw_Phdr *phdr = GET_LIST_ENTRY(iter, Elfw_Phdr);
        if(phdr->data->p_type == PT_LOAD) {
            if ((uintptr_t) phdr->data->p_vaddr <= addr && addr <= phdr->data->p_vaddr + phdr->data->p_filesz) {
                *output = (addr_to_rva(bin, addr) + segment_rva_to_offset_delta(bin, phdr));
                return LIBWORM_SUCCESS;
            }
        }
    }
    return LIBWORM_ERROR;
}

int offset_to_addr(Elfw_Bin *bin, int offset, int *output) {
    struct list_head *iter;

    BIN_ITER_PHDRS (iter, bin) {
        Elfw_Phdr *phdr = GET_LIST_ENTRY(iter, Elfw_Phdr);
        if(phdr->data->p_type == PT_LOAD) {
            if(phdr->data->p_offset <= offset && offset <= PAGE_ALIGN_UP(phdr->data->p_offset + phdr->data->p_filesz)) {
                *output = (offset + (phdr->data->p_vaddr - phdr->data->p_offset));
                return LIBWORM_SUCCESS;
            }
        }
    }
    return LIBWORM_ERROR;
}

void resolve_dynamic_symbols(Elfw_Bin *bin) {

    init_list_head (&bin->dynamic_symbols.list);

    for (int i = 0; i < bin->pltgot_num; i++) {
        Elfw_Sym *sym = (Elfw_Sym *)calloc (1, sizeof(Elfw_Sym));
        sym->data = &bin->dynsym[i];
        list_add_tail (&sym->list, &bin->dynamic_symbols.list);
    }
}

void resolve_dynamic(Elfw_Bin *bin) {
    ElfW(Dyn) *dynamic, *entry;
    int offset;

    dynamic = (ElfW(Dyn) *)&bin->data[bin->dynamic_phdr->p_offset];
    bin->rel_num = 0;

    init_list_head (&bin->dynamic.list);
    for (int i = 0; ; i++) {
        Elfw_Dyn *dyn_node = (Elfw_Dyn *)calloc (1, sizeof (Elfw_Dyn));
        entry = &dynamic[i];
        dyn_node->data = entry;

        list_add_tail (&dyn_node->list, &bin->dynamic.list);

        switch (entry->d_tag) {
            case DT_SYMTAB:
                if (addr_to_offset (bin, (uintptr_t)entry->d_un.d_ptr, &offset) ==  LIBWORM_SUCCESS) {
                    bin->dynsym = (ElfW(Sym *)) &bin->data[offset];
                }
                break;
            case DT_STRTAB:
                if (addr_to_offset(bin, (uintptr_t)entry->d_un.d_ptr, &offset) == LIBWORM_SUCCESS) {
                    bin->dynstr = &bin->data[offset];
                }
                break;
            case DT_STRSZ:
                bin->dynsym_num = (int)entry->d_un.d_val;
                break;
            case DT_REL:
            case DT_RELA:
                if (addr_to_offset (bin, (uintptr_t)entry->d_un.d_ptr, &offset) == LIBWORM_SUCCESS) {
                    bin->rel = (ElfW(Rel) *) &bin->data[offset];
                }
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

int resolve_pltgot(Elfw_Bin *bin) {
    int got_offset;
    if (addr_to_offset(bin, bin->pltgot_addr, &got_offset) == LIBWORM_ERROR) {
        return LIBWORM_ERROR;
    }
    PtrW(uint) *got_data = (PtrW(uint) *)&bin->data[got_offset];

    init_list_head(&bin->pltgot.list);
    for (int i = 0; i < bin->pltgot_num + PLTGOTLDENT; i++) {
        Elfw_Ptr *ptr = (Elfw_Ptr *)calloc (1, sizeof(Elfw_Ptr));
        ptr->data = &got_data[i];
        list_add_tail(&ptr->list, &bin->pltgot.list);
    }
    return LIBWORM_SUCCESS;
}

int is_code_address(Elfw_Bin *bin, int address) {
    if(bin->code_phdr->p_vaddr <= address && address <= bin->code_phdr->p_vaddr + bin->code_phdr->p_filesz) {
        return LIBWORM_SUCCESS;
    }
    return LIBWORM_ERROR;
}

int resolve_plt(Elfw_Bin *bin) {
    PtrW(uint) plt_entry;
    Elfw_Ptr *got_entry;
    struct list_head *iter;
    int i = 0;

    BIN_ITER_GOTPLT(iter, bin) {
        got_entry = GET_LIST_ENTRY(iter, Elfw_Ptr);
        if (is_code_address(bin, *got_entry->data) == LIBWORM_SUCCESS) {
            bin->plt_addr = ((*got_entry->data >> 4) << 4) - 0x10;
            break;
        }
    }
    if (addr_to_offset(bin, bin->plt_addr, (int *) &plt_entry) == LIBWORM_ERROR){
        return LIBWORM_ERROR;
    }

    while(true) {
        int offset;
        /*cheking that the plt_addr points to the plt first entry*/
        if(addr_to_offset(bin, bin->plt_addr, &offset) == LIBWORM_ERROR) {
            fprintf(stderr, "Error parsing plt");
            return LIBWORM_ERROR;
        }

        if (*(uint16_t *)&bin->data[offset] != 0x35ff) {
            bin->plt_addr += 2;
        } else {
            break;
        }
    }

    init_list_head(&bin->plt.list);
    for (i = 0; i <= bin->pltgot_num; i++) {
        Elfw_Plt *plt = (Elfw_Plt *)calloc (1, sizeof(Elfw_Plt));
        plt->addr = (PtrW(uint) *)((uint8_t *)bin->plt_addr + i * PLTENT);
        list_add_tail(&plt->list, &bin->plt.list);
    }
    return LIBWORM_SUCCESS;
}

void resolve_relocs(Elfw_Bin *bin) {

    init_list_head(&bin->relocs.list);
    for (int i = 0; i < bin->relocs_num; i++) {
        Elfw_Rel *entry = (Elfw_Rel *) calloc(1, sizeof(Elfw_Rel));
        entry->data = &bin->rel[i];
        list_add_tail(&entry->list, &bin->relocs.list);
    }
}

int get_got_entry_from_dynamic_symbol(Elfw_Bin *bin, Elfw_Ptr **got_entry, char *sym_name) {
    struct list_head *iter;
    Elfw_Rel *rel;
    char *dyn_name;
    ElfW(Sym) *sym;
    int sym_index=0, offset=0, i;

    BIN_ITER_RELOCS(iter, bin) {
        rel = GET_LIST_ENTRY(iter, Elfw_Rel);
        sym_index = __ELF_NATIVE_CLASS == 64 ? ELF64_R_SYM(rel->data->r_info) :  ELF32_R_SYM(rel->data->r_info);
        sym = &bin->dynsym[sym_index];
        if (get_dynamic_symbol_name(bin, sym, &dyn_name) ==  LIBWORM_SUCCESS) {
            if (!(strlen(dyn_name) - strlen(sym_name)) && !strncmp(dyn_name, sym_name, strlen(sym_name))) {
                break;
            }
        }
        offset++;
    }
    offset -= bin->rel_num;

    i = 0;
    BIN_ITER_GOTPLT(iter, bin) {
        if (i++ == offset + PLTGOTLDENT) {
            *got_entry = GET_LIST_ENTRY(iter, Elfw_Ptr);
            return LIBWORM_SUCCESS;
        }
    }
    return LIBWORM_ERROR;
}

int set_symbol_got_entry(Elfw_Bin *bin, char *sym_name, PtrW(uint) value) {
    Elfw_Ptr *got_ent;
    if(get_got_entry_from_dynamic_symbol(bin, &got_ent, sym_name) == LIBWORM_ERROR) {
        return LIBWORM_ERROR;
    }
    *got_ent->data = value;
    return LIBWORM_SUCCESS;
}

int bin_load_elf(Elfw_Bin **_bin, const char *path,  int prot, int flags) {
    struct stat st;
    Elfw_Bin *bin;

    bin = (Elfw_Bin*)calloc (1, sizeof(Elfw_Bin));
    *_bin = bin;

    if (!bin) {
        perror ("calloc");
        return LIBWORM_ERROR;
    }
    if ((bin->fd = open (path, O_RDWR)) < 0) {
        perror ("open");
        return LIBWORM_ERROR;
    }
    if (fstat (bin->fd, &st) < 0) {
        perror ("fstat");
        return LIBWORM_ERROR;
    }
    bin->data = mmap (NULL, (size_t)PAGE_ALIGN_UP (st.st_size), prot, flags, bin->fd, 0);
    if (bin->data == MAP_FAILED) {
        perror("mmap");
        return LIBWORM_ERROR;
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
    return LIBWORM_SUCCESS;
}

int bin_elf_new(Elfw_Bin **_bin, const char *path, int size) {
   Elfw_Bin *bin;

    bin = (Elfw_Bin*)calloc (1, sizeof(Elfw_Bin));
    *_bin = bin;

    if (!bin) {
        perror ("calloc");
        return LIBWORM_ERROR;
    }
    if ((bin->fd = open (path, O_RDWR | O_CREAT, 044)) < 0) {
        perror ("open");
        return LIBWORM_ERROR;
    }

    bin->data = mmap (NULL, (size_t)PAGE_ALIGN_UP(size), PROT_READ | PROT_WRITE, MAP_PRIVATE, bin->fd, 0);
    if (bin->data == MAP_FAILED) {
        perror("mmap");
        return LIBWORM_ERROR;
    }

    bin->size = size;
    bin->path = path;
    return LIBWORM_SUCCESS;
}

