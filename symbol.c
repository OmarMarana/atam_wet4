#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "elf64.h"
#include <sys/mman.h>
#include "symbol.h"

#define GLOBAL 1
#define SYMTAB 2
#define STRTAB 3
#define ET_EXEC 2

static bool isElfFile(char* exe_file_name) {
    bool is_elf = false;
    FILE* elf = fopen(exe_file_name, "r");
    char* our_magic = malloc(sizeof(char) * 5);

    // check if file given is of elf type
    if(fread(our_magic, 1, 4, elf) < 4) {
        free(our_magic);
        fclose(elf);
        return false;
    } 
    our_magic[4] = '\0';
    if (strcmp(our_magic + 1, "ELF") == 0){ // 7f 45 4c 46 --->(ASCII) _ELF
        is_elf = true;
    } 
    free(our_magic);
    fclose(elf);
    return is_elf;
}

long find_symbol(char* symbol_name, char* exe_file_name, unsigned int* local_count){
    *local_count = 0;
    
    if(!isElfFile(exe_file_name)) return -3;
    
    int elf_fd = open(exe_file_name, O_RDONLY);
    if(elf_fd == -1) return -7;
    
    void *elf = mmap(NULL, lseek(elf_fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, elf_fd, 0);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)elf;
    if(elf_header->e_type != ET_EXEC) return -3;
    Elf64_Shdr* section_h_arr = (Elf64_Shdr*)((char*)elf + elf_header->e_shoff);
    Elf64_Shdr sh_str_section = section_h_arr[elf_header->e_shstrndx];

    char *sh_str_tbl = (char*)elf + sh_str_section.sh_offset;
    Elf64_Half sections_amount = elf_header->e_shnum;
    
    Elf64_Sym *symtab;
    char *strtab;
    int symbols_amount = 0;
    for(int i = 0; i < sections_amount; i++) {
        char* section_name = sh_str_tbl + section_h_arr[i].sh_name;
        if(!strcmp(".symtab", section_name) || section_h_arr[i].sh_type == SYMTAB){
            symtab = (Elf64_Sym*)((char*)elf + section_h_arr[i].sh_offset);
            symbols_amount = section_h_arr[i].sh_size / section_h_arr[i].sh_entsize;
        }
        else if(!strcmp(".strtab", section_name) || section_h_arr[i].sh_type == STRTAB){
            if((char*)elf + section_h_arr[i].sh_offset != sh_str_tbl){
                strtab = ((char*)elf + section_h_arr[i].sh_offset);
            }
        }
    }
    for(int i = 0; i < symbols_amount; i++){
        char* curr_symbol_name = strtab + symtab[i].st_name;
        if(!strcmp(symbol_name, curr_symbol_name)) {
            if(ELF64_ST_BIND(symtab[i].st_info) == GLOBAL) {
                close(elf_fd);
                return symtab[i].st_value;
            }
            else {
                *local_count += 1;
            }
        }
    }
    close(elf_fd);
    return *local_count == 0 ? -1 : -2;
}