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
    uint64_t str_tbl_offset = shdr[h.e_shstrndx].sh_offset;
    Elf64_Shdr symtabH, strtabH;
    for (int i = 0; i < h.e_shnum; ++i) {
	char * str = parseString(file, str_tbl_offset + shdr[i].sh_name);
        bool chk = !strcmp(str, ".symtab");
	cleanStr(str);
        free(str);
        if(chk){
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

return 0;
}

unsigned long searchInPLT(char* symbol_name, char* exe_file_name, int* error_val, unsigned long * got_address) {

FILE* file = fopen(exe_file_name, "r");
    Elf64_Ehdr h;
    fread(&h, sizeof(Elf64_Ehdr), 1, file);

    Elf64_Shdr* shdr = malloc(h.e_shnum * sizeof(Elf64_Shdr));
    fseek(file, h.e_shoff, SEEK_SET);
    fread(shdr, sizeof(Elf64_Shdr), h.e_shnum, file);

    Elf64_Shdr relaPltH, dynsymH, strtabH;
char* str;
bool chk;
    uint64_t str_tbl_offset = shdr[h.e_shstrndx].sh_offset, address_of_plt = 0 ,plt_entry_size = 0 ;
    for (int i = 0; i < h.e_shnum; ++i) {
	str = parseString(file, str_tbl_offset + shdr[i].sh_name);
        chk = !strcmp(str, ".rela.plt");
	cleanStr(str);
        free(str);
        if(chk){
            relaPltH = shdr[i];
        }
	str = parseString(file, str_tbl_offset + shdr[i].sh_name);
        chk = !strcmp(str, ".dynsym");
	cleanStr(str);
        free(str);
        if(chk){
            dynsymH = shdr[i];
        }
 	str = parseString(file, str_tbl_offset + shdr[i].sh_name);
        chk = !strcmp(str, ".plt");
	cleanStr(str);
        free(str);
        if(chk){
            address_of_plt = shdr[i].sh_addr;
            plt_entry_size = shdr[i].sh_entsize;
        }
	str = parseString(file, str_tbl_offset + shdr[i].sh_name);
        chk = !strcmp(str, ".dynstr");
	cleanStr(str);
        free(str);
	if(chk){
		strtabH = shdr[i];
	}
    }



    Elf64_Rela* relaplt = malloc(relaPltH.sh_size);
    fseek(file, relaPltH.sh_offset, SEEK_SET);
    fread(relaplt, relaPltH.sh_entsize, relaPltH.sh_size / relaPltH.sh_entsize, file);

  


Elf64_Sym* dynsym = malloc(dynsymH.sh_size);
    fseek(file, dynsymH.sh_offset, SEEK_SET);
    fread(dynsym, dynsymH.sh_entsize, dynsymH.sh_size / dynsymH.sh_entsize, file);

    



    Elf64_Sym sym;
    uint64_t right_index = 0;
    for (uint64_t i = 0; i < dynsymH.sh_size / dynsymH.sh_entsize; ++i) {
        sym = dynsym[i];
        char* str = parseString(file, strtabH.sh_offset + sym.st_name);

        bool chk = !strcmp(str, symbol_name);
        cleanStr(str);
        free(str);
        if(chk){
            right_index = i;
		break;
        }
    }


    uint64_t index_at_plt = 0;
    Elf64_Rela rela;
    for (uint64_t i = 0; i < relaPltH.sh_size / relaPltH.sh_entsize; ++i) {
        rela = relaplt[i];
        if(ELF64_R_SYM(rela.r_info) == right_index){
            index_at_plt = i+1;
            *got_address = rela.r_offset;
        }
    }
 uint64_t final = address_of_plt + index_at_plt * plt_entry_size;

    return final;
  

return 0;
}


void run_debugger(pid_t child_pid, unsigned long addr, char* exe_file_name, unsigned long got_addr){
    bool first_time = true;
    int wait_status;
    struct user_regs_struct regs, temp;
    waitpid(child_pid, &wait_status, 0);
	unsigned long data_trap, data;
    //Find main and wait till it starts to make sure loading is done
    int err = 0;
    
	//wait(&wait_status);

    int counter = 1;
    //Place breakpoint in func
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);

    if (data < 0) {
        perror("ptrace7");
        return;
    }
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) data_trap) < 0) {
        perror("ptrace8");
        return;
    }

    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
        perror("ptrace8");
        return;
    }
    wait(&wait_status);

    while(WIFSTOPPED(wait_status)) {
        //Print rdi (first parameter)
        if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) < 0) {
            perror("ptrace9");
            return;
        }
        printf("PRF:: run #%d first parameter is %d\n", counter, (int)regs.rdi);

        //Handle breakpoint in func and remove it
        if (ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) data) < 0) {
            perror("ptrace");
            return;
        }
        regs.rip -= 1;
        if (ptrace(PTRACE_SETREGS, child_pid, NULL, &regs)) {
            perror("ptrace10");
            return;
        }
	//bool first = true;

        //Track rsp to find out when the func returned
        do {
            if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
                perror("ptrace11");
                return;
            }
            wait(wait_status);

            if (ptrace(PTRACE_GETREGS, child_pid, NULL, &temp) < 0) {
                perror("ptrace12");
                return;
            }
		/*if(first && regs.rsp != temp.rsp)
		{
			first = false;
		}*/
//first ||
        } while (regs.rsp + 8 != temp.rsp);
	
        printf("PRF:: run #%d returned with %d\n", counter, (int)temp.rax);

        if(got_addr != 0 && first_time) {
            first_time = false;
            data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) got_addr, NULL);
            if (data < 0) {
                perror("ptrace135");
                return;
            }
            addr = data;
        }
        //Place breakpoint in func
        ++counter;
        data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);
        if (data < 0) {
            perror("ptrace13");
            return;
        }
        data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        if (ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) data_trap) < 0) {
            perror("ptrace14");
            return;
        }

        if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) {
            perror("ptrace15");
            return;
        }
        wait(&wait_status);
    }
}

pid_t run_target(char *const argv[]){
    pid_t pid = fork();

    if(pid > 0){
        return pid;
    }
    else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
	printf("%s", argv[0]);
        execv(argv[0], argv);
	//return 0;
    } else {
        perror("fork");
        exit(1);
    }
}

int main(int argc, char *const argv[]) {
	int err = 0;
	
	unsigned long addr = find_symbol(argv[1], argv[2], &err);
    unsigned long got_addr = 0;
	if (err == -2){
		printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
		return 0;
}
	else if (err == -1){
		printf("PRF:: %s not found!\n", argv[1]);
		return 0;
}
	else if (err == -3){
		printf("PRF:: %s not an executable! :(\n", argv[2]);
		return 0;
}
	else if (err == -4){
        addr = searchInPLT(argv[1], argv[2], &err, &got_addr);
    }

    //printf("%s will be loaded to 0x%lx\n", argv[1], addr);

    pid_t child_pid = run_target(argv + 2);
    run_debugger(child_pid, addr, argv[2], got_addr);

	return 0;
}