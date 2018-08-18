#include "libx.h"

int main(int argc, char **argv) {
    Elfx_Bin *bin;
    struct list_head *iter;

    if (!(bin = bin_load_elf ("/home/ulexec/ls", PROT_READ | PROT_WRITE, MAP_PRIVATE))) {
        fprintf (stderr, "bin_load_elf failed");
        return -1;
    }

    /* Iterate through program headers */
    BIN_ITER_PHDRS(iter, bin) {
        Elfx_Phdr *phdr = GET_LIST_ENTRY (iter, Elfx_Phdr);
        printf ("0x%lx\n" , phdr->data->p_paddr);
    }
    /*Iterate through section headers*/
    BIN_ITER_SHDRS(iter, bin) {
        Elfx_Shdr *shdr = GET_LIST_ENTRY (iter, Elfx_Shdr);
        printf ("%s\n", get_section_name (bin, shdr->data));
    }
    /*Iterate through symtab symbols*/
    BIN_ITER_SYMBOLS(iter, bin) {
        Elfx_Sym *sym = GET_LIST_ENTRY (iter, Elfx_Sym);
        printf ("%s\n", get_symbol_name (bin, sym->data));
    }
    /*Iterate through dynsym symbols*/
    BIN_ITER_DYNAMIC_SYMBOLS(iter, bin) {
        Elfx_Sym *sym = GET_LIST_ENTRY (iter, Elfx_Sym);
        printf ("%s\n", get_dynamic_symbol_name (bin, sym->data));
    }
    /*Iterate through dynamic entries*/
    BIN_ITER_DYNAMIC(iter, bin) {
        Elfx_Dyn *dyn = GET_LIST_ENTRY (iter, Elfx_Dyn);
        printf ("0x%lx\n", dyn->data->d_un.d_ptr);
    }
    /*Iterate through relocations*/
    BIN_ITER_RELOCS(iter, bin) {
        Elfx_Rel *rel = GET_LIST_ENTRY(iter, Elfx_Rel);
        printf ("0x%lx\n", rel->data->r_offset);
    }
    /*Iterate through .got.plt section entries*/
    BIN_ITER_GOTPLT(iter, bin) {
        Elfx_Ptr *ptr = GET_LIST_ENTRY(iter, Elfx_Ptr);
        printf ("0x%lx\n", *ptr->data);
    }
    /*Iterate through .plt section entries*/
    BIN_ITER_PLT(iter, bin) {
        Elfx_Plt *plt = GET_LIST_ENTRY(iter, Elfx_Plt);
        printf ("0x%lx -->0x%lx\n", plt->addr, *(uint64_t*)plt->bin_ptr);
    }
    /*Overwritting GOT Entry of symbol*/
    if(set_symbol_got_entry(bin, "fwrite", 0x400050)) {
        fprintf(stderr, "set_symbol_got_entry failed");
    }

    /*Helper functions for offset <-> address conversion*/
    printf("0x%lx\n", offset_to_addr(bin, 0x0));
    printf("0x%lx\n", addr_to_offset(bin, 0x400000));

    /*Saving changes to original file*/
    bin_save_elf(bin);

    bin_unload_elf (bin);
    return 0;
}
