#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "elf64.h"
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define GLOBAL 1
#define INVALID_FILE -1
#define FUNC_NOT_FOUND -2
#define FUNC_NOT_GLOBAL -3
#define ET_EXEC 2


void* check_if_file_is_valid(const char* file_name) 
{
    FILE* ELF = fopen(file_name, "r");
    char magic [4];
    if (!ELF) 
    {
        //printf("cheching if open succeeded %s\n", file_name);
        return NULL;
    }
    if (fread(magic, 1, 4, ELF) < 4 || magic[0] != 127 || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') 
    {
        //printf("cheching if elf\n");
        fclose(ELF);
        return NULL;
    }
    int elf_fd = open(file_name, O_RDONLY);
    if (elf_fd == -1) 
    {
        //printf("cheching open filename\n");
        fclose(ELF);
        return NULL;
    }
    void *elf = mmap(NULL, lseek(elf_fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, elf_fd, 0);
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)elf;
    if (elf_header->e_type != ET_EXEC) 
    {
        printf("PRF:: <prog name> not an executable! :(\n");
        fclose(ELF);
        close(elf_fd);
        return NULL;
    }
    //printf("file is valid\n");
    return elf;
}

bool check_file_and_func(const char* file_name, const char* func_name, Elf64_Half* sec_index_of_func, unsigned long* addr) 
{
    void* elf = check_if_file_is_valid(file_name);
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
    if (!found) 
    {
        printf("PRF:: %s not found!\n", func_name);
        return false;
    }
    printf("PRF:: %s is not a global symbol! :(\n", func_name);
    return false;
}


unsigned long find_GOT_entry(const char* file_name, const char* func_name)
{ 
    int elf_fd = open(file_name, O_RDONLY);
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
    printf("hello, getting GOT");
    for(int i = 0; i < sections_amount; i++)
    {
        char* section_name = sh_str_tbl + section_h_arr[i].sh_name;
        if(!strcmp(".dynsym", section_name))
        {
            dynsym = (Elf64_Sym*)((char*)elf + section_h_arr[i].sh_offset);
        }
        else if(!strcmp(".rela.plt", section_name))
        {
            rela_plt = (Elf64_Rela*)((char*)elf + section_h_arr[i].sh_offset);
            rela_entries_num = section_h_arr[i].sh_size / section_h_arr[i].sh_entsize;
        }
        else if (!strcmp(".dynstr", section_name))
        {
            strtab = ((char*)elf + section_h_arr[i].sh_offset);
        }
    }
    int i = 0;
    for(; i < rela_entries_num; i++) 
    {
        int dynsym_index = ELF64_R_SYM(rela_plt[i].r_info);
        char* curr_symbol_name = strtab + dynsym[dynsym_index].st_name;
        if(strcmp(func_name, curr_symbol_name) == 0)
        {
            printf("bye, got GOT");
            break;
        }
    }
    close(elf_fd);
    return rela_plt[i].r_offset;
}


void run_sys_debugger(pid_t child_pid, unsigned long func_addr, Elf64_Half UND, const char* file_name, const char* func_name) 
{
    int wait_status;
    struct user_regs_struct regs; 
    unsigned long long int wanted_rsp;
    unsigned long r_a;
    unsigned long func_addr_GOT_entry;
    int call_counter = 0;
    wait( &wait_status);

    if (UND == SHN_UNDEF)
    {
        func_addr_GOT_entry = find_GOT_entry(file_name, func_name);
        //is the func addr saved in the GOT as 8 bytes for sure? or can it be less than 8 bytes for mem utilization reasons?
        func_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr_GOT_entry, NULL);
    } 

    long func_start_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL);
    // define data_trap
    unsigned long func_start_data_trap = (func_start_data & 0xFFFFFFFFFFFFFF00) | 0xCC;

    while(!WIFEXITED(wait_status))
    {
        printf("1\n");
        // adding BP at func
        ptrace(PTRACE_POKETEXT ,child_pid, (void*)func_addr, (void*)func_start_data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        if (WIFEXITED(wait_status)) 
        {
            printf("done\n");
            return;
        }
        //child stopped at breakpoint at the start of function
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)func_start_data);
        regs.rip -= 1;
        wanted_rsp = regs.rsp;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        //does peek read towards higher addresses?
        r_a = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)wanted_rsp, NULL);
        long r_a_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)r_a, NULL);
        unsigned long r_a_data_trap = (r_a_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT ,child_pid, (void*)r_a, (void*)r_a_data_trap);

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        ptrace(PTRACE_POKETEXT, child_pid, (void*)r_a, (void*)r_a_data);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rip -= 1;
        // at this point the child is stopped at the r_a
        unsigned long long int curr_rsp = regs.rsp - 8;
        int counter = 0;
        while(wanted_rsp != curr_rsp)
        {
            counter++;
            //printf("%lld, %lld\n", wanted_rsp, curr_rsp);
            printf("2\n");
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            // do one instruction
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0)
            {
                perror("ptrace");
                return;
            }
            wait(&wait_status);
            //if after one instruction we reach r_a
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            if (regs.rsp == wanted_rsp + 8) 
            {
                printf("here?\n");
                break;
            }
            // return BP to r_a, wait for it to reach,
            ptrace(PTRACE_POKETEXT, child_pid, (void*)r_a, (void*)r_a_data_trap);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            wait(&wait_status);
            //child stopped at breakpoint at r_a
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)r_a, (void*)r_a_data);
            regs.rip -= 1;
            curr_rsp = regs.rsp - 8;
        }
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        call_counter++;
        printf("PRF:: run #%d returned with %lld\n", call_counter, regs.rax);
        if (UND == SHN_UNDEF)
        {
            func_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr_GOT_entry, NULL);
            UND = 1;
        }
        
    }
    //printf("%d\n", call_counter);
}


pid_t run_target(char** argv) 
{
    //printf("running target\n");
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
        execv((argv+2)[0], (argv+2));
		//execl(exefile_name, exefile_name, NULL);
	} 
    else 
    {
		perror("fork");
        exit(1);
    }
}


int main(int argc, char** argv)
{
    const char* func_name = argv[1];
    const char* exefile_name = argv[2];
    Elf64_Half sec_index_of_func = SHN_UNDEF;
    unsigned long addr;
    if (!check_file_and_func(exefile_name, func_name, &sec_index_of_func, &addr)) 
    {
        return 0;
    }
    pid_t child_pid = run_target(argv);
    run_sys_debugger(child_pid, addr, sec_index_of_func, exefile_name, func_name);
    return 0;
}