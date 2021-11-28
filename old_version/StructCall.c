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
    long orig_rax, rax;
    long params[3] = {0};
    int status = 0;
    int insyscall = 0;
    struct user_regs_struct regs;
    child = fork();
    if(child == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
    }else
    {
        while(1)
        {
            wait(&status);
            if(WIFEXITED(status))
                break;
            orig_rax = ptrace(PTRACE_PEEKUSER, child, 8*ORIG_RAX, NULL);
            if(orig_rax == SYS_write)
            {
                if(insyscall ==0)
                {
                    insyscall = 1;
                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    printf("write called with %llu,%llu, %llu\n",regs.rdi,
                                            regs.rsi,regs.rdx);
                }else
                {
                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    printf("write returned with %lld\n", regs.rax);
                    insyscall=0 ;
                }
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        }
    }
    return 0;
}
