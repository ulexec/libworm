#include <stdio.h>
#include <wchar.h>
#include "elfx.h"


int main(int argc, char **argv) {
    Elfx_Bin *bin;
    struct list_head *iter;

    if (!(bin = load_elf("/home/ulexec/a.out", PROT_READ | PROT_WRITE, MAP_PRIVATE))) {
        fprintf(stderr, "load_elf failed");
    }

    bin_iter_phdrs(iter, bin) {
        Elfx_Phdr *phdr = list_entry(iter, Elfx_Phdr, list);
        printf("0x%lx\n" , phdr->data->p_paddr);
    }

    bin_iter_shdrs(iter, bin) {
        Elfx_Shdr *shdr = list_entry(iter, Elfx_Shdr, list);
        printf("%s\n", get_section_name(bin, shdr));
    }

    unload_elf(bin);
    return 0;
}
