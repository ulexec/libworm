#include <elf.h>
#include "libx.h"

int main(int argc, char **argv) {
    Elfx_Bin *bin;
    struct list_head *iter;

    if (!(bin = bin_load_elf("/home/ulexec/ls", PROT_READ | PROT_WRITE, MAP_PRIVATE))) {
        fprintf(stderr, "bin_load_elf failed");
        return -1;
    }

    bin_iter_phdrs(iter, bin) {
        Elfx_Phdr *phdr = bin_list_entry(iter, Elfx_Phdr);
        printf("0x%lx\n" , phdr->data->p_paddr);
    }
    bin_iter_shdrs(iter, bin) {
        Elfx_Shdr *shdr = bin_list_entry(iter, Elfx_Shdr);
        printf("%s\n", get_section_name(bin, shdr));
    }
    bin_iter_symbols(iter, bin) {
        Elfx_Sym *sym = bin_list_entry(iter, Elfx_Sym);
        printf("%s\n", get_symbol_name(bin, sym));
    }
    bin_iter_dynamic_symbols(iter, bin) {
        Elfx_Sym *sym = bin_list_entry(iter, Elfx_Sym);
        printf("%s\n", get_dynamic_symbol_name(bin, sym));
    }
    bin_iter_dynamic(iter, bin) {
        Elfx_Dyn *dyn = bin_list_entry(iter, Elfx_Dyn);
        printf("0x%lx\n", dyn->data->d_un.d_ptr);
    }
    bin_unload_elf(bin);
    return 0;
}
