#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
      
      long getSysCallNo(int pid, struct pt_regs *regs)
      {
              long scno = 0;
                  ptrace(PTRACE_GETREGS, pid, NULL, regs);
                      scno = ptrace(PTRACE_PEEKTEXT, pid, (void *)(regs->ARM_pc - 4), NULL); 
                          if(scno == 0)
                                      return 0;
                                                 
                                                     if (scno == 0xef000000) 
                                                             { 
                                                                         scno = regs->ARM_r7; 
                                                                             } 
                                                                                 else 
                                                                                         { 
                                                                                                     if ((scno & 0x0ff00000) != 0x0f900000) 
                                                                                                                 { 
                                                                                                                                 return -1; 
                                                                                                                                         } 
                                                                                                                                               
                                                                                                                                                       scno &= 0x000fffff; 
                                                                                                                                                           }
                                                                                                                                                               return scno;    
      }
            
            void tracePro(int pid)
            {
                    long scno=0;
                        struct pt_regs regs;
                         
                             scno = getSysCallNo(pid, &regs);
                                 printf("Target syscall no:%ld\n",scno);
            }
                  
                  int main(int argc, char *argv[])
                  {   
                          if(argc != 2) 
                                  {
                                             printf("please input pid...\n");
                                                    return 1;
                                                        }
                                                                  
                                                                      pid_t traced_process;
                                                                          int status;
                                                                              traced_process = atoi(argv[1]);
                                                                               
                                                                                   if( ptrace(PTRACE_ATTACH, traced_process, NULL, NULL) != 0)
                                                                                           {
                                                                                                       printf("Trace process failed:%d.\n", errno);
                                                                                                            return 1;
                                                                                                                }
                                                                                                                    while(1)
                                                                                                                            {
                                                                                                                                        wait(&status);
                                                                                                                                                if(WIFEXITED(status))
                                                                                                                                                            {
                                                                                                                                                                            break;
                                                                                                                                                                                    }
                                                                                                                                                                                            tracePro(traced_process);
                                                                                                                                                                                                    ptrace(PTRACE_SYSCALL, traced_process, NULL, NULL);
                                                                                                                                                                                                        }
                                                                                                                                                                                                              
                                                                                                                                                                                                                  ptrace(PTRACE_DETACH, traced_process, NULL, NULL);
                                                                                                                                                                                                                            
                                                                                                                                                                                                                                return 0;
                  }
