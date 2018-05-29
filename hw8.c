#include <features.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <string.h>

char* regs[23] = {"REG_R8", "REG_R9", "REG_R10", "REG_R11", "REG_R12",
  "REG_R13",
  "REG_R14",
  "REG_R15",
  "REG_RDI",
  "REG_RSI",
  "REG_RBP",
  "REG_RBX",
  "REG_RDX",
  "REG_RAX",
  "REG_RCX",
  "REG_RSP",
  "REG_RIP",
  "REG_EFL",
  "REG_CSGSFS",                
  "REG_ERR",
  "REG_TRAPNO",
  "REG_OLDMASK",
  "REG_CR2"};
  
jmp_buf j;

void handler2(int nSignum, siginfo_t* si, void* vcontext){
    if(si->si_signo == SIGSEGV){
        longjmp(j, 1);
    }    
}

void dump(int i){
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    //longjmp(j, 0);
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler2;
    if(sigaction(SIGSEGV, &action, NULL) < 0){
        perror("SIGSEGV in dump.\n");
        exit(1);
    }
    if(setjmp(j) == 0){
        printf("address: 0x%x\n", i);
    }
    else{
        printf("bad address: 0x%x\n", i);
	longjmp(j, 0);
    }
}  


void handler1(int nSignum, siginfo_t* si, void* vcontext) {
if(si->si_signo == SIGSEGV){
  printf("Segmentation fault %p\n", si->si_addr);
  ucontext_t* context = (ucontext_t*)vcontext;
  for(int i = 0; i < NGREG; i++){
        printf("%s 0x%x\n", regs[i], (unsigned int)context->uc_mcontext.gregs[i]);  
  }
  char* addr = si->si_addr;
printf("DUMP\n");
  for(int i = addr - 10; i < addr + 10; i++){
      dump(i);
  }
    exit(1);
}
}
  
int main(int argc, char** argv) {
    printf("START\n");
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler1;
    if(sigaction(SIGSEGV, &action, NULL) < 0){
        perror("sigaction: SIGSEGV");
        exit(1);
    }
	char* c = "1234567";
	c[9] = '1';
    printf("FINISH");
  
    return 0;
}
