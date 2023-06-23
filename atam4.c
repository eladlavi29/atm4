#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 
#define	GLOBAL	1	//Core file
#define	UNDEFINED	0	//Core file


char* parseString(FILE* file, uint64_t offset){
    fseek(file, offset, SEEK_SET);
    int len = 0;
    while (getc(file) != NULL){
        len++;
    }
    char* output = malloc(sizeof(char) * (len + 1));
    fseek(file, offset, SEEK_SET);
    fread(output, sizeof(char), len, file);
    return output;
}

void cleanStr(char* str){
	int i = 0;
	if(str == NULL) return;

	while(str[i] != '\0'){
		str[i]='\0';
		i++;
	}
}

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {

    FILE* file = fopen(exe_file_name, "r");
    Elf64_Ehdr h;
    fread(&h, sizeof(Elf64_Ehdr), 1, file);
    if (h.e_type != ET_EXEC) {
        *error_val = -3;
        fclose(file);
        return 0;
    }


    Elf64_Shdr* shdr = malloc(h.e_shnum * sizeof(Elf64_Shdr));
    fseek(file, h.e_shoff, SEEK_SET);
    fread(shdr, sizeof(Elf64_Shdr), h.e_shnum, file);

    Elf64_Shdr symtabH, strtabH;
    for (int i = 0; i < h.e_shnum; ++i) {
        if(shdr[i].sh_type == 2){
            symtabH = shdr[i];
            break;
        }
    }

    strtabH = shdr[symtabH.sh_link];



    Elf64_Sym* symtab = malloc(symtabH.sh_size);
    fseek(file, symtabH.sh_offset, SEEK_SET);
    fread(symtab, symtabH.sh_entsize, symtabH.sh_size / symtabH.sh_entsize, file);

    bool found = false;
    Elf64_Sym sym;
    for (int i = 0; i < symtabH.sh_size / symtabH.sh_entsize; ++i) {
        sym = symtab[i];
        char* str = parseString(file, strtabH.sh_offset + sym.st_name);
        bool chk = !strcmp(str, symbol_name);
	    cleanStr(str);
        free(str);
        if(chk){
            found = true;
            if(ELF64_ST_BIND(sym.st_info) == GLOBAL){
                if(sym.st_shndx == UNDEFINED){
                    *error_val = -4;
			        fclose(file);
                    free(shdr);
                    free(symtab);
                    return 0;
                }
                else{
                    *error_val = 1;
                    fclose(file);
                    free(shdr);
                    free(symtab);
                    return sym.st_value;
                }
            }
        }


    }
    if(!found){
        *error_val = -1;
        fclose(file);
        free(shdr);
        free(symtab);
        return 0;
    }
    else{
        *error_val = -2;
        fclose(file);
        free(shdr);
        free(symtab);
        return 0;
    }

}

void run_debugger(pid_t child_pid, unsigned long addr, char* exe_file_name){
    int wait_status;
    struct user_regs_struct regs;
    waitpid(child_pid, &wait_status, 0);

    //Find main and wait till it starts to make sure loading is done
    int err = 0;
    unsigned long main_addr = find_symbol("main", exe_file_name, &err);
    if(err < 0){
        perror("Main not found");
    }

    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)main_addr, NULL);
    if(data < 0){
        perror("ptrace");
        return;
    }
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if(ptrace(PTRACE_POKETEXT, child_pid, (void*)main_addr, (void*)data_trap) < 0){
        perror("ptrace");
        return;
    }

    if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0){
        perror("ptrace");
        return;
    }
    wait(&wait_status);

    //Handle breakpoint in main and remove it
    if(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) < 0){
        perror("ptrace");
        return;
    }
    if(ptrace(PTRACE_POKETEXT, child_pid, (void*)main_addr, (void*)data) < 0){
        perror("ptrace");
        return;
    }
    regs.rip -= 1;
    if(ptrace(PTRACE_SETREGS, child_pid, NULL, &regs)){
        perror("ptrace");
        return;
    }

    int counter = 1, rsp;
    //Place breakpoint in func
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);

    printf("func command: 0x%lx\n", data);

    if(data < 0){
        perror("ptrace");
        return;
    }
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if(ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap) < 0){
        perror("ptrace");
        return;
    }

    if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0){
        perror("ptrace");
        return;
    }
    wait(&wait_status);

    //Print rdi (first parameter)
    if(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) < 0){
        perror("ptrace");
        return;
    }
    printf("PRF:: run #%d first parameter is %lld\n", counter, regs.rdi);

    //Handle breakpoint in func and remove it
    if(ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data) < 0){
        perror("ptrace");
        return;
    }
    regs.rip -= 1;
    if(ptrace(PTRACE_SETREGS, child_pid, NULL, &regs)){
        perror("ptrace");
        return;
    }
/*
    //Print return value
    //Track rsp to find out when the func returned
    rsp = regs.rsp;
    printf("rsp: 0x%lx\n", regs.rsp);
    while(WIFSTOPPED(wait_status)){
        if(ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0){
            perror("ptrace");
            return;
        }
        wait(wait_status);

        if(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) < 0){
            perror("ptrace");
            return;
        }

        printf("rsp: 0x%lx\n", regs.rsp);

        if(regs.rsp > rsp)
            break;
    }
    printf("PRF:: run #%d returned with %lld\n", counter, regs.rax);
    */

    if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0){
        perror("ptrace");
        return;
    }
}

pid_t run_target(const char* func){
    pid_t pid = fork();

    if(pid > 0){
        return pid;
    }
    else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execl(func, func, NULL);

    } else {
        perror("fork");
        exit(1);
    }
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4){
        //Omer (a.k.a my best friend in the whole world) 's responsibility
    }

    //printf("%s will be loaded to 0x%lx\n", argv[1], addr);

    pid_t child_pid = run_target(argv[2]);
    run_debugger(child_pid, addr, argv[2]);

	return 0;
}