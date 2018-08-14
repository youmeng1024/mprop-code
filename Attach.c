#include <sys/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc,char *argv[])
{
    pid_t traced_process;
    struct user_regs_struct regs;
    long ins;
    if(argc != 2)
    {
        puts("no pid input ");
        exit(1);
    }
    traced_process = atoi(argv[1]);
    printf("try to trace pid:%u\n",traced_process);
    if(ptrace(PTRACE_ATTACH,traced_process,NULL,NULL)==-1)
        perror("trace error:1\n");

    wait(NULL);
    if(ptrace(PTRACE_GETREGS,traced_process,NULL,&regs))
        perror("trace error:2\n");

    ins = ptrace(PTRACE_PEEKTEXT,traced_process,regs.rip,NULL);
    if(ins==-1)
        perror("trace error:3\n");

    printf("EIP:%llx Instruction executed: %lx\n",regs.rip,ins);

    if(ptrace(PTRACE_DETACH,traced_process,NULL,NULL)==-1)
        perror("trace error:");

    return 0;

}
