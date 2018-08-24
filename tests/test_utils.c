#include "../worm.h"

int main(int argc, char **argv) {
    Elfw_Bin *bin;
    struct list_head *iter;

    if (bin_load_elf (&bin, "/home/ulexec/Desktop/ls", PROT_READ | PROT_WRITE, MAP_PRIVATE) == LIBWORM_ERROR) {
        fprintf (stderr, "bin_load_elf failed");
        return LIBWORM_ERROR;
    }

    /* Iterate through program headers */
    BIN_ITER_PHDRS(iter, bin) {
        Elfw_Phdr *phdr = GET_LIST_ENTRY (iter, Elfw_Phdr);
        printf ("0x%lx\n" , phdr->data->p_paddr);
    }
    /*Iterate through section headers*/
    BIN_ITER_SHDRS(iter, bin) {
        char *section_name;
        Elfw_Shdr *shdr = GET_LIST_ENTRY (iter, Elfw_Shdr);
        if(get_section_name(bin, shdr->data, &section_name) == LIBWORM_SUCCESS) {
            printf("%s\n", section_name);
        }
    }
    /*Iterate through symtab symbols*/
    BIN_ITER_SYMBOLS(iter, bin) {
        char *symbol_name;
        Elfw_Sym *sym = GET_LIST_ENTRY (iter, Elfw_Sym);
        if (get_symbol_name(bin, sym->data, &symbol_name) == LIBWORM_SUCCESS) {
            printf("%s\n", symbol_name);
        }
    }
    /*Iterate through dynsym symbols*/
    BIN_ITER_DYNAMIC_SYMBOLS(iter, bin) {
        char *symbol_name;
        Elfw_Sym *sym = GET_LIST_ENTRY (iter, Elfw_Sym);
        if(get_dynamic_symbol_name(bin, sym->data, &symbol_name) == LIBWORM_SUCCESS) {
            printf ("%s\n", symbol_name);
        }

    }
    /*Iterate through dynamic entries*/
    BIN_ITER_DYNAMIC(iter, bin) {
        Elfw_Dyn *dyn = GET_LIST_ENTRY (iter, Elfw_Dyn);
        printf ("0x%lx\n", dyn->data->d_un.d_ptr);
    }
    /*Iterate through relocations*/
    BIN_ITER_RELOCS(iter, bin) {
        Elfw_Rel *rel = GET_LIST_ENTRY(iter, Elfw_Rel);
        printf ("0x%lx\n", rel->data->r_offset);
    }
    /*Iterate through .got.plt section entries*/
    BIN_ITER_GOTPLT(iter, bin) {
        Elfw_Ptr *ptr = GET_LIST_ENTRY(iter, Elfw_Ptr);
        printf ("0x%lx\n", *ptr->data);
    }
    /*Iterate through .plt section entries*/
    BIN_ITER_PLT(iter, bin) {
        Elfw_Plt *plt = GET_LIST_ENTRY(iter, Elfw_Plt);
        printf ("%p\n", plt->addr);
    }
    /*Overwritting GOT Entry of symbol*/
    if(set_symbol_got_entry(bin, "__libc_start_main", 0x400050) == LIBWORM_ERROR) {
        fprintf(stderr, "set_symbol_got_entry failed");
        return LIBWORM_ERROR;
    }

    /*Helper functions for offset <-> address conversion*/
    int addr;
    offset_to_addr(bin, 0xe28, &addr);
    printf("0x%x\n", addr);

    int offset;
    addr_to_offset(bin, 0x61ee28, &offset);
    printf("0x%x\n", offset);

    /*Saving changes to original file*/
    bin_update_elf(bin, sizeof(ElfW(Ehdr)), 0);

    /*Deallocating the loaded binary*/
    bin_unload_elf (bin);
    return LIBWORM_SUCCESS;
}
