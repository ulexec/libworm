#include <elf.h>
#include "libx.h"

int main(int argc, char **argv) {
    Elfx_Bin *bin;
    struct list_head *iter;

    if (!(bin = bin_load_elf ("/home/ulexec/ls", PROT_READ | PROT_WRITE, MAP_PRIVATE))) {
        fprintf (stderr, "bin_load_elf failed");
        return -1;
    }

    /* Iterate through program headers */
    bin_iter_phdrs(iter, bin) {
        Elfx_Phdr *phdr = get_list_entry (iter, Elfx_Phdr);
        printf ("0x%lx\n" , phdr->data->p_paddr);
    }
    /*Iterate through section headers*/
    bin_iter_shdrs(iter, bin) {
        Elfx_Shdr *shdr = get_list_entry (iter, Elfx_Shdr);
        printf ("%s\n", get_section_name (bin, shdr));
    }
    /*Iterate through symtab symbols*/
    bin_iter_symbols(iter, bin) {
        Elfx_Sym *sym = get_list_entry (iter, Elfx_Sym);
        printf ("%s\n", get_symbol_name (bin, sym));
    }
    /*Iterate through dynsym symbols*/
    bin_iter_dynamic_symbols(iter, bin) {
        Elfx_Sym *sym = get_list_entry (iter, Elfx_Sym);
        printf ("%s\n", get_dynamic_symbol_name (bin, sym));
    }
    /*Iterate through dynamic entries*/
    bin_iter_dynamic(iter, bin) {
        Elfx_Dyn *dyn = get_list_entry (iter, Elfx_Dyn);
        printf ("0x%lx\n", dyn->data->d_un.d_ptr);
    }
    /*Iterate through relocations*/
    bin_iter_relocs(iter, bin) {
        Elfx_Rel *rel = get_list_entry(iter, Elfx_Rel);
        printf ("0x%lx\n", rel->data->r_offset);
    }
    /*Iterate through .got.plt entries*/
    bin_iter_pltgot(iter, bin) {
        Elfx_Ptr *ptr = get_list_entry(iter, Elfx_Ptr);
        printf ("0x%lx\n", *ptr->data);
    }

    bin_unload_elf (bin);
    return 0;
}
