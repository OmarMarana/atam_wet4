#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "elf64.h"
#include <sys/mman.h>

#define GLOBAL 1
#define INVALID_FILE -1
#define FUNC_NOT_FOUND -2
#define FUNC_NOT_GLOBAL -3
#define ET_EXEC 2


void* check_if_file_is_valid(char* file_name) 
{
    FILE* ELF = fopen(file_name, "r");
    char magic [4];
    if (!ELF) {
        return NULL;
    }
    if (fread(magic, 1, 4, ELF) < 4 || magic[0] != 127 || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') 
    {
        fclose(ELF);
        return NULL;
    }
    int elf_fd = open(file_name, O_RDONLY);
    if (elf_fd == -1) 
    {
        fclose(ELF);
        return NULL;
    }
    void *elf = mmap(NULL, lseek(elf_fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, elf_fd, 0);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)elf;
    if (elf_header->e_type != ET_EXEC) {
        printf("PRF:: <prog name> not an executable! :(\n");
        fclose(ELF);
        close(elf_fd);
        return NULL;
    }
    return elf;
}

bool check_file_and_func(char* file_name, char* func_name, Elf64_Half* sec_index_of_func, unsigned long* addr) 
{
    void* elf = checkIfFileIsvalid(file_name);
    if (!elf) 
    {
        return false;
    }
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)elf;
    Elf64_Shdr* section_h_arr = (Elf64_Shdr*)((char*)elf + elf_header->e_shoff);
    Elf64_Shdr section_h_str_table = section_h_arr[elf_header->e_shstrndx];
    char *sh_str_tbl = (char*)elf + section_h_str_table.sh_offset;
    Elf64_Half sections_amount = elf_header->e_shnum;
    Elf64_Sym *symtab;
    char *strtab;
    int symbols_amount = 0;
    for(int i = 0; i < sections_amount; i++)
    {
        char* section_name = sh_str_tbl + section_h_arr[i].sh_name;
        if (!strcmp(".symtab", section_name)) //|| section_h_arr[i].sh_type == SYMTAB
        { 
            symtab = (Elf64_Sym*)((char*)elf + section_h_arr[i].sh_offset);
            symbols_amount = section_h_arr[i].sh_size / section_h_arr[i].sh_entsize;
        }
        else if (!strcmp(".strtab", section_name)) // || section_h_arr[i].sh_type == STRTAB
        {
            strtab = ((char*)elf + section_h_arr[i].sh_offset);
        }
    }

    bool found = false;

    for(int i = 0; i < symbols_amount; i++)
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;
        if (!strcmp(func_name, curr_symbol_name))
        {
            found = true;
            if (ELF64_ST_BIND(symtab[i].st_info) == GLOBAL)
            {
                
                *sec_index_of_func = symtab[i].st_shndx;
                *addr = symtab[i].st_value;
                return true;
            }
        }
    }
    if (!found) {
        printf("PRF:: <function name> not found!\n");
        return false;
    }
    printf("PRF:: <function name> is not a global symbol! :(\n");
    return false;
}


unsigned long find_addr_in_GOT(char* file_name, char* func_name)
{ 
    int elf_fd = open(exe_file_name, O_RDONLY);
    void *elf = mmap(NULL, lseek(elf_fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, elf_fd, 0);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)elf;
    Elf64_Shdr* section_h_arr = (Elf64_Shdr*)((char*)elf + elf_header->e_shoff);
    Elf64_Shdr sh_str_section = section_h_arr[elf_header->e_shstrndx];
    char *sh_str_tbl = (char*)elf + sh_str_section.sh_offset;
    Elf64_Half sections_amount = elf_header->e_shnum;
    Elf64_Sym *dynsym;
    Elf64_Rela *rela_plt;
    char *strtab;
    int rela_entries_num = 0;
    for(int i = 0; i < sections_amount; i++)
    {
        char* section_name = sh_str_tbl + section_h_arr[i].sh_name;
        if(!strcmp(".dynsym", section_name))
        {
            dynsym = (Elf64_Sym*)((char*)elf + section_h_arr[i].sh_offset);
        }
        else if(!strcmp(".rela.plt", section_name))
        {
            rela_plt = ((Elf64_Rela*)elf + section_h_arr[i].sh_offset);
            rela_entries_num = section_h_arr[i].sh_size / section_h_arr[i].sh_entsize;
        }
        else if (!strcmp(".strtab", section_name))
        {
            strtab = ((char*)elf + section_h_arr[i].sh_offset);
        }
    }
    int i = 0;
    for(; i < rela_entries_num; i++) 
    {

        int dynsym_index = ELF64_R_SYM(rela_plt[i].r_info);
        char* curr_symbol_name = strtab + dynsym[i].sh_name;
        if(strcmp(func_name, curr_symbol_name) == 0)
        {
           break; 
        }
    }
    return *((unsigned long*)(rela_plt[i].r_offset));
}


void run_sys_debugger(pid_t child_pid, unsigned long func_addr, bool UND, char* file_name, char* func_name) 
{
    int wait_status;
    struct user_regs_struct regs; 
    unsigned long curr_rsp;
    unsigned long r_a;
    wait( &wait_status);

    if (UND) 
    {
        func_addr = find_addr_in_GOT(file_name, func_name);
        long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL);
        // define data_trap
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        // adding the first BP
        ptrace(PTRACE_POKETEXT child_pid, (void*)func_addr, (void*)data_trap);
        
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status);
        //child stopped at breakpoint at the start of function
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        
        ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data);
        regs.rip -= 1;
        curr_rsp = regs.rsp;
        r_a = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)curr_rsp, NULL);

        ptrace(PTRACE_POKETEXT child_pid, (void*)r_a, (void*)data_trap);

    }
    
    
    
    


    
}


pid_t run_target(const char* exefile_name, char** argv){
    pid_t pid = fork();
    if (pid > 0)
    {
        return pid;
    } 
    else if (pid == 0) 
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) 
        {
			perror("ptrace");
			exit(1);
        }
		execl(exefile_name, *(argv + 2), NULL);
	} 
    else 
    {
		perror("fork");
        exit(1);
    }
}


int main(int argc, char** argv)
{
    char* func_name = argv[1];
    char* exefile_name = argv[2];
    Elf64_Half sec_index_of_func = SHN_UNDEF;
    unsigned long addr;
    if (!check_file_and_func(exefile_name, func_name, &sec_index_of_func, &addr)) 
    {
        return 0;
    }


    pid_t child_pid = run_target(exefile_name, argv);
    run_sys_debugger(child_pid, symbol_addr);
    return 0;
}