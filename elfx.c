//
// Created by ulexec on 12/08/18.
//

#include "elfx.h"
#include "listx.h"

uint8_t * get_section_name(Elfx_Bin *bin, Elfx_Shdr *shdr) {
    if (!bin->shstrtab) {
        return NULL;
    }
    return &bin->shstrtab[shdr->data->sh_name];
}

uint8_t * get_symbol_name(Elfx_Bin *bin, Elfx_Sym *sym) {
    if(!bin->strtab) {
        return NULL;
    }
    return &bin->strtab[sym->data->st_name];
}

int unload_elf(Elfx_Bin *bin) {
    close(bin->fd);
    free(bin);
    return 0;
}

void resolve_symbols(Elfx_Bin *bin) {

    init_list_head (&bin->symbols.list);
    for (int i = 0; i < bin->symnum; i++) {
        Elfx_Sym *sym_entry = (Elfx_Sym *)calloc(1, sizeof(Elfx_Sym));
        sym_entry->data = &bin->symtab[i];
        list_add_tail(&sym_entry->list, &bin->symbols.list);
    }
}

void resolve_sections(Elfx_Bin *bin) {
    ElfW(Shdr) *shdr;

    shdr = (ElfW(Shdr) *)(bin->data + bin->ehdr->e_shoff);
    bin->shstrtab = &bin->data[shdr[bin->ehdr->e_shstrndx].sh_offset];

    init_list_head (&bin->shdrs.list);
    for (int i = 0; i < bin->ehdr->e_shnum; i++) {
        Elfx_Shdr *shdr_entry = (Elfx_Shdr *) calloc(1, sizeof(Elfx_Shdr));
        shdr_entry->data = &shdr[i];

        list_add_tail(&shdr_entry->list, &bin->shdrs.list);

        switch (shdr[i].sh_type) {
            case SHT_SYMTAB:
                if (!strcmp (get_section_name(bin, shdr_entry), ".symtab")) {
                    bin->symtab = (ElfW(Sym) *)&bin->data[shdr_entry->data->sh_offset];
                    bin->symnum = (int)(shdr_entry->data->sh_size / sizeof(ElfW(Sym)));
                    ElfW(Shdr) *strtab_shdr = &shdr[shdr_entry->data->sh_link];
                    bin->strtab = (char *)&bin->data[strtab_shdr->sh_offset];
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
        Elfx_Phdr *phdr_entry = (Elfx_Phdr *)calloc(1, sizeof(Elfx_Phdr));
        phdr_entry->data = &phdr[i];

        list_add_tail(&phdr_entry->list, &bin->phdrs.list);

        switch (phdr[i].p_type) {
            case PT_LOAD:
                if (!phdr[i].p_offset) {
                    bin->code_phdr = &phdr[i];
                } else {
                    bin->data_phdr = &phdr[i];
                }
                break;
            case PT_DYNAMIC:
                bin->dynamic_phdr = &phdr[i];
                break;
            default:
                break;
        }
    }
}

Elfx_Bin * load_elf(const char *path, int prot, int flags) {
    int fd;
    struct stat st;
    Elfx_Bin *bin;

    bin = (Elfx_Bin*)calloc (1, sizeof(Elfx_Bin));
    if (!bin) {
        perror ("calloc");
        return NULL;
    }
    if ((fd = open (path, O_RDWR)) < 0) {
        perror ("open");
        return NULL;
    }
    if (fstat (fd, &st) < 0) {
        perror ("fstat");
        return NULL;
    }

    bin->data = mmap (NULL, (size_t)PAGE_ALIGN_UP(st.st_size), prot, flags, fd, 0);
    if (bin->data == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }

    bin->path = strdup(path);
    bin->size = (int) st.st_size;
    bin->ehdr = (ElfW(Ehdr) *)bin->data;
    bin->type = bin->ehdr->e_type;
    bin->entry = bin->ehdr->e_entry;

    resolve_sections(bin);
    resolve_segments(bin);
    resolve_symbols(bin);

    return bin;
}