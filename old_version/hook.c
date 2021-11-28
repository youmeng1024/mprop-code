#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/reg.h>
#include <sys/unistd.h>
#include <sys/user.h>
#include <string.h>

#define LONG_SIZE 8
void putdata(pid_t child,long addr,char* str,int  len)
{
        char *laddr = str;
        int i=0,j=len/LONG_SIZE;
        union u {
            long val;
            char chars[5];
         } word;
         while(i<j)
          {
            memcpy(word.chars,laddr,LONG_SIZE);
            if(ptrace(PTRACE_POKEDATA,child,addr+i*LONG_SIZE,word.val) ==-1)
                perror("trace error put1\n");
            i++;
            laddr+=LONG_SIZE;
          }
            j=len%LONG_SIZE;
            if(j!=0)
            {
              memcpy(word.chars,laddr,j);
              if(ptrace(PTRACE_POKEDATA,child,addr+i*LONG_SIZE,word.val)==-1)
                   perror("trace error put2\n");
                                                                                  }

}

void getdata(pid_t child, long addr,char *str,int len)
{
            char *laddr = str;
            int i = 0,j = len/LONG_SIZE;
            union u{
                long val;
                char chars[LONG_SIZE];
             } word;
             while(i<j)
             {
               word.val = ptrace(PTRACE_PEEKDATA,child, addr + i*LONG_SIZE, NULL);
               if(word.val == -1)
                                                                                                                                    perror("trace error in get1\n");
                                                                                                                                                memcpy(laddr,word.chars,LONG_SIZE);
                                                                                                                                                            ++i;
                                                                                                                                                                        laddr += LONG_SIZE;
                                                                                                                                                                                }
                                                                                                                                                                                        j = len%LONG_SIZE;
                                                                                                                                                                                                if(j!=0)
                                                                                                                                                                                                            {
                                                                                                                                                                                                                            word.val = ptrace(PTRACE_PEEKDATA,child, addr+i*LONG_SIZE,NULL);
                                                                                                                                                                                                                                        if(word.val == -1)
                                                                                                                                                                                                                                                            perror("trace error in get2\n");
                                                                                                                                                                                                                                                                        memcpy(laddr,word.chars,j);
                                                                                                                                                                                                                                                                                }
                                                                                                                                                                                                                                                                                        str[len] = '\0';
}

void printBytes(const char* tip,char* codes,int len)
{
        int i;
        printf("%s :",tip);
                for(i=0;i<len;i++)
                            printf("%02x ",(unsigned char)codes[i]);
                                puts("");
}



int main(int argc,char *argv[])
{
    long addr = 0x0000000000400566;
    pid_t pid = atoi(argv[1]);
    struct user_regs_struct regs;
    char inCode[8] = {0x90,0x90,0x90,0x90,0x90,0xbf,0x4d,0x06};
    if(ptrace(PTRACE_ATTACH,pid,NULL,NULL) == -1)
        perror("trace attach error");
    wait(NULL);
    int flag=0;
    char old[10];
    while(1)
    {
        if(ptrace(PTRACE_SYSCALL,pid,NULL,NULL) ==-1)
               perror("trace contine error"); 
        wait(NULL);
        if(ptrace(PTRACE_GETREGS,pid,NULL,&regs) ==-1)
            perror("trace getregs error");
        printf("rdi:%llx\n",regs.rdi);
        printf("rip:%llx\n",regs.rip);
        getchar();
        regs.rip = addr;
        ///
        getdata(pid,addr+9,old,14);
        printBytes("before:--",old,14);
        putdata(pid,addr+9,inCode,8);
        ///
        getdata(pid,addr+9,old,14);
        printBytes("after:--",old,14);

        if(flag==0)
        {
            if(ptrace(PTRACE_SETREGS,pid,NULL,&regs)== -1)
                 perror("trace setregs error");
            flag=1;
        }

    }
    return 0;
}
