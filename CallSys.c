#include <sys/ptrace.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>

int main()
{
    pid_t child;
    long orig_eax, eax;
    long params[3];
    int status;
    int insyscall=0;
    child = fork();

    if(child == 0 ){
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }else{
        while(1){
            wait(&status);
            if(WIFEXITED(status))
                break;
            orig_eax = ptrace(PTRACE_PEEKUSER, child, 8*ORIG_RAX, NULL);
            if(orig_eax == SYS_write){
                if(insyscall ==0){
                    insyscall=1;
                    params[0] = ptrace(PTRACE_PEEKUSER,child, 8*RDI, NULL);
                    params[1] = ptrace(PTRACE_PEEKUSER, child, 8*RSI, NULL);
                    params[2] = ptrace(PTRACE_PEEKUSER, child, 8*RDX, NULL);
                    printf("write call with %ld, %ld, %ld\n",params[0],params[1]                                                            ,params[2]);
                }else{
                    eax = ptrace(PTRACE_PEEKUSER, child, 8*RAX, NULL);
                    printf("write returned with %ld\n",eax);
                }
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }

    }
    return 0;
}
