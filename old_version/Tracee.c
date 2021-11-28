#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define LONG_SIZE 8
 

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

void putdata(pid_t child,long addr,char* str,int  len)
{
    char *laddr = str;
    int i=0,j=len/LONG_SIZE;
    union u {
        long val;
        char chars[LONG_SIZE];
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
        word.chars[j] = '\0';
        if(ptrace(PTRACE_POKEDATA,addr+i*LONG_SIZE,word.val)==-1)
            perror("trace error put2\n");
    }
}


void printBytes(const char* tip,char* codes,int len)
{
    int i;
    printf("%s :",tip);
    for(i=0;i<len;i++)
        printf("%02x ",(unsigned char)codes[i]);
    puts("");
}

/*
#define CODE_SIZE 8
int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        puts("no pid input");
        exit(1);
    }
    pid_t traced_process;
    struct user_regs_struct regs;
    long ins;
    char code[LONG_SIZE] = {0xcc};
    char backup[LONG_SIZE];
    traced_process = atoi(argv[1]);
    printf("try to attach pid:%u\n",traced_process);
    if(ptrace(PTRACE_ATTACH, traced_process, NULL,NULL)==-1)
        perror("trace attach error");
    wait(NULL);
    if(ptrace(PTRACE_GETREGS,traced_process,NULL,&regs) ==-1)
        perror("tarce get regs error");

    ////////
    getdata(traced_process,regs.rip,backup,CODE_SIZE);
    printBytes("get tracee instuction",backup,CODE_SIZE);
    puts("try to set breakpoint");
    printBytes("set breakpoint instruction",code,LONG_SIZE);
    putdata(traced_process,regs.rip,code,CODE_SIZE);
    if(ptrace(PTRACE_CONT,traced_process,NULL,NULL)==-1)
        perror("trace continue error");
    wait(NULL);
    puts("the process stopped Press <Enter> to continue");
    getchar();
    printBytes("place breakpoint instruction with tracee instruction",backup,LONG_SIZE);
    putdata(traced_process,regs.rip,backup,CODE_SIZE);
    ptrace(PTRACE_SETREGS,traced_process,NULL,&regs);
    ptrace(PTRACE_DETACH,traced_process,NULL,NULL);
    return 0;
}
*/



/*
int main(int argc,char *argv[])
{
    if(argc != 2)
    {
        puts("no pid input");
        exit(1);
    }

    pid_t traced_process;
    struct user_regs_struct regs;
    long ins;
    char c;
    traced_process = atoi(argv[1]);
    printf("try to attach pid : %u\n",traced_process);
    if(ptrace(PTRACE_ATTACH,traced_process,NULL,NULL)==-1)
        perror("trace attach errori");
    wait(NULL);
    while(1){
        if(ptrace(PTRACE_GETREGS,traced_process,NULL,&regs)==-1)
            perror("trace get regs error");
        printf("this rip:%llx\n",regs.rip);
        getchar();
        ptrace(PTRACE_SINGLESTEP,traced_process,NULL,NULL);
        wait(NULL);
    }
    ptrace(PTRACE_DETACH,traced_process,NULL,NULL);
}
*/

long freespaceaddr(pid_t pid)
{
        FILE *fp;
        char filename[30];
        char line[85];
        long addr;
        long end;
        char str[20];
        char tmp[20];
        sprintf(filename, "/proc/%d/maps", pid);
        //sprintf(filename, "proc/%d/mem", pid);
        fp = fopen(filename, "r");
        if(fp == NULL)
        exit(1);
        int i=0;
        char c[3];
        while(fgets(line, 85, fp) != NULL) {
           sscanf(line, "%lx-%*s %s %*s %s", &addr,tmp,str);
        //    printf("++:%s",line);
           //getdata(pid,addr,c,2);
           //printf("%s||----:%d   %d\n",tmp ,c[0],c[1]);
           if(strcmp(tmp,"r-xp")==0)
           {
               if(i==1){
                 break;
               }
               i++;  
           }   
        }
        fclose(fp);
        return addr;
}

#define CODE_SIZE 48
int main(int argc, char *argv[])
{
    if(argc<2)
    {
        puts("no pid input");
        exit(1);
    }
    pid_t tracee = atoi(argv[1]);
    char code_inject[CODE_SIZE] = {0xeb,0x13,0x5e,0xb8,0x01,0x00,0x00,0x00,0xbf,0x01,0x00,0x00,0x00,0xba,0x0d,0x00,0x00,0x00,0x0f,0x05,0xcc,0xe8,0xe8,0xff,0xff,0xff,0x48,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0xa};
    char code_backup[CODE_SIZE];
    struct user_regs_struct oldregs,regs;
    long ins;
    if(ptrace(PTRACE_ATTACH,tracee,NULL,NULL)==-1)
        perror("attach error");
    wait(NULL);
    puts("attach success");
    ptrace(PTRACE_GETREGS,tracee,NULL,&regs);
    //long addr = regs.rip;
    long addr = freespaceaddr(tracee)+2;
    printf("found rip addr:%lx\n",addr);
    getdata(tracee,addr,code_backup,CODE_SIZE);
    putdata(tracee,addr,code_inject,CODE_SIZE);
    memcpy(&oldregs,&regs,sizeof(regs));
    regs.rip = addr;
    printf("new rip: %llx\n",regs.rip);
    if(ptrace(PTRACE_SETREGS,tracee,NULL,&regs)==-1)
        perror("set regs error");
    puts("replace instructions success, continue tracee");
    if(ptrace(PTRACE_CONT,tracee,NULL,NULL)==-1)
        perror("continue tracee error");
    wait(NULL);
    ptrace(PTRACE_GETREGS,tracee,NULL,&regs);
    printf("tracee end at rip: %llx\n:",regs.rip);
    puts("tracee has stopped,putting back original instructions");
    putdata(tracee,addr,code_backup,CODE_SIZE);
    if(ptrace(PTRACE_SETREGS,tracee,NULL,&oldregs)==-1)
        perror("put original instuctions error");
  //  ptrace(PTRACE_DETACH,tracee,NULL,NULL);
    return 0;

}

