#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <stdlib.h>
#include <sys/reg.h>
#include <string.h>
#include <asm/mman.h>
#include <dlfcn.h>

#define CPSR_T_MASK  ( 1u << 5 )  


//获取目标进程的模块地址（一般有多个，第一个是r-xp）
void* get_module_addr(pid_t pid,const char *module_name,long *end)
{
    FILE *fp;
    char filePath[128];
    char fileLine[1024];
    if(pid < 0)
        snprintf(filePath, sizeof(filePath), "/proc/self/maps");
    else
        snprintf(filePath, sizeof(filePath), "/proc/%d/maps",pid);
    
    fp = fopen(filePath,"r");
    if(fp==NULL)
    {
        printf("get Module addre open fp error\n");
        return NULL;
    }
    unsigned long addr_start =0,addr_end = 0;
    while(fgets(fileLine,sizeof(fileLine),fp))
    {
        if(strstr(fileLine, module_name))
        {
            if(2==sscanf(fileLine,"%8lx-%8lx",&addr_start,&addr_end))
                break;
        }
    }
    fclose(fp);    
    printf("library :%s %lx-%lx, pid:%d\n",module_name, addr_start,addr_end, pid);
    *end = addr_end;
    return (void*)addr_start;
}
//获取模块的函数地址
void* get_func_addr(pid_t pid, const char *module_name,const void *func_offset_addr)
{
    //第三个参数是函数在自己的模块或者进程里的偏移地址，需要本人手动分析
    //其他人的代码都是分析so的，自己的程序将so加载，然后算出函数位置-so的位置得到偏移量，这样子就可以加上目标进程的so位置得到目标进程的函数的位置了。然而我这边是想要修改进程函数，不再so里面，因此偏移量我想办法自己计算吧。
    void *local_addr;
    local_addr = get_module_addr(pid,module_name,NULL);
    return (void*)((unsigned long)local_addr+(unsigned long)func_offset_addr);
}



//向进程写入数据
int ptrace_setData(pid_t pid,const void *addr, const void *data, int size)
{
    int count = size / sizeof(long);
    int remain = size % sizeof(long);
    long buf;
    int i=0;
    for(i=0;i<count;i++)
    {
        memcpy(&buf,data,sizeof(long));
        if(ptrace(PTRACE_POKETEXT,pid,addr,buf)==-1)
            printf("write data error:%d\n",i);
        data = ((long*)data)+1;
        addr = ((long*)addr)+1;
    }
    if(remain>0)
    {
        buf = ptrace(PTRACE_PEEKTEXT,pid,addr,NULL);
        memcpy(&buf,data,remain);
        if(ptrace(PTRACE_POKETEXT,pid,addr,buf)==-1)
           {
               perror("wirte remain data error");
               return -1;
           }
    }
}

//读取进程的内存数据
char* ptrace_getData(pid_t pid, unsigned long addr, unsigned long size)
{
    int count = size / sizeof(long);
    int remain = size % sizeof(long);
    char *str = (char*)malloc(size+1);
    memset(str,0,size+1);
    int LONG_SIZE = sizeof(long);
    char *point=str;
    union u
    {
        long val;
        char chars[LONG_SIZE];
    } d;
    
    int i;
    for(i=0;i<count;i++)
    {
        d.val = ptrace(PTRACE_PEEKTEXT,pid,addr,0);
        memcpy(point,d.chars,LONG_SIZE);
        addr+=LONG_SIZE;
        point+=LONG_SIZE;
    }    

    if(remain>0)
    {
        d.val=ptrace(PTRACE_PEEKTEXT,pid,addr,0);
        memcpy(point,d.chars,remain);
    }
    return str;
}


//调用目标进程函数
int ptrace_call(pid_t pid, const void* addr, const long *parameters, int num, struct pt_regs *regs)
{
    int i;
    //前四个参数分别放入r0-4,其他的按右到左放入栈里。
    //如果需要传入字符串等信息需要提前将数据写入目标进程。
    
    for(i=0;i<num && i<4;++i)
    {
        regs->uregs[i] = parameters[i];
    }
    
    if(i<num)
    {
        printf("write %d parameters to stack\n",num - i);
        regs->ARM_sp -= (num-i)*sizeof(long);
        if(ptrace_setData(pid,(void*)regs->ARM_sp,&parameters[i],(num-i)*sizeof(long))==-1)
        {
            printf("write to stack error\n");
            return -1;
        }
    }
    
    //设置pc寄存器
    regs->ARM_pc = (long)addr;
    //arm每个指令4字节，thumb每个指令2字节，在跳转子函数进入thumb函数时，pc地址会+1表示进入thumb指令状态（也学是因为thubm函数有
    //一行声明？），因此thumb函数里的所有pc地址都不会是偶数。。因为每次pc计数+2....所以，可以按照pc的第0bit来判断是arm或者thumb
    // #define CPSR_T_MASK  ( 1u << 5 )  
    // 猜测这里需要将cpsr寄存器设置为1表示thumb。而因为thumb函数的话，pc指向地址为偶数，但是跳转的时候会自动+1,不需要我们操心，
    //因此直接讲pc末尾置0即可。

    if(regs->ARM_pc & 1)//thumb情况
    {
        regs->ARM_pc &=(~1u);
        regs->ARM_cpsr |= ~CPSR_T_MASK;
    }
    else
        regs->ARM_cpsr &= ~CPSR_T_MASK;

    //设置lr寄存器值为0,当函数返回时进程会接收到异常信号而停止运行
    //这里进行设置只是为了看看是否有效吧，，经测试不设置，还是可以的，这个只是
    //为了我们自己认为的弄出个信号吧。对于使用ptrace_cont运行的子进程，它会在3种情况下进入暂停状态：①下一次系统调用；②子进程退出；③子进程的执行发生错误信号为0xb7f，低2字节表示子进程是退出（0x0）还是暂停（0x7f），高2字节字节表示退出信号为11（SIGSEGV）
    regs->ARM_lr = 0;
    
    if(ptrace(PTRACE_SETREGS,pid,NULL,regs)==-1)
        perror("ptrace call setregs errpr");

    if(ptrace(PTRACE_CONT,pid,NULL,NULL)==-1)
        perror("ptrace call continue error");

    printf("wait for stopping....\n");
    
    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while(stat != 0xb7f)
    {
        if(ptrace(PTRACE_CONT,pid,NULL,NULL)==-1)
            perror("inject continue error");
        return -1;
        waitpid(pid,&stat,WUNTRACED);
    }
    printf("inject success\n");
    return 0;
}



long getSysCallNo(int pid, struct pt_regs *regs)
{
        long scno = 0;
        ptrace(PTRACE_GETREGS, pid, NULL, regs);
        scno = ptrace(PTRACE_PEEKTEXT, pid, (void *)(regs->ARM_pc - 4), NULL); 
        if(scno == 0)
            return 0;
        if(scno == 0xef000000) 
        { 
           scno = regs->ARM_r7; 
           //printf("this EABI\n");
        }
        else
        { 
        if((scno & 0x0ff00000) != 0x0f900000) 
        { 
           return -1; 
        } 
        scno &= 0x000fffff; 
        //printf("OABI is this\n");
        }
        return scno;    
}


int main(int argc,char* argv[])
{
    if(argc != 2)
    {
        puts("no pid input");
        exit(1);
    }
    long scno=0;
    FILE *fp;
    pid_t pid;
    pid = atoi(argv[1]);
    long baseAddr,*end=malloc(sizeof(long));
    long parm[4];
    char buf[2048],*tmp;
    struct pt_regs regs,old;
    printf("try to attach pid:%u\n",pid);
    sprintf(buf,"/proc/%d/maps",pid);
   /* fp = fopen(buf,"r");
    if(fp==NULL)
    {
        perror("open maps error");
    }
    while(fgets(buf,sizeof(buf),fp))
    {
        if(strstr(buf,"r-xp"))
        {
            tmp = strtok(buf,"-");
            baseAddr = strtoul(tmp,NULL,16);
            break;
        }
    }
    */
    char module[20] = "inject";
    long offset = 0x42c;
//    baseAddr =(long) get_func_addr(pid, module,(void *)offset);

    char ch[20] = "init";
    baseAddr = (long) get_module_addr(pid,ch, end);
    printf("the baseAddr,,the end :%lx ---%lx\n",baseAddr,*end);
    if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1)
        perror("trace attach error");
    wait(NULL);
    char *str;
    char ro[5]={0x72,0x6f,0x2e,0x00,0x00};
    char sd[5]={0x62,0x62,0x62,0x00,0x00};
    printf("===%s\n",ro);
    for(baseAddr;baseAddr<*end;baseAddr++)
    {
        str = ptrace_getData(pid,baseAddr,4);
        if(strcmp(str,ro)==0)
            {
                printf("i found it!!!!:%lx\n",baseAddr);
                break;
            }
    }
    ptrace_setData(pid,(void *)baseAddr,sd,4);
    printf("not find\n");
    
/*
    while(1)
    {
        wait(NULL);
        scno=getSysCallNo(pid,&regs);
        printf("the scno num is:%d\n",scno);
        if(scno==__NR_write)
        {
           printf("found the write Func\n");
         //  printf("the params:%lx\n",regs.ARM_pc);
           // memcpy(&old,&regs, sizeof(struct pt_regs));
           //ptrace_call(pid,(void *)(baseAddr),parm,0,&regs);
           //ptrace(PTRACE_SETREGS,pid,NULL,&old);
         

          ptrace(PTRACE_GETREGS,pid,NULL,&regs);
          printf("ths sp top=====:%lx\n",regs.ARM_sp);
          char* str= ptrace_getData(pid,regs.ARM_r1,15);
          printf("input text :%s",str);
          printf("\n--------------\n");
          long end=0xffc44000;
          long start=0xffc65000;
          for(start;start>end;start-=4)
          {
                str=ptrace_getData(pid,start,4);
                printf("the item is:%lx\n",str);
          }

          


            break;
        }
        
        if(ptrace(PTRACE_GETREGS,pid,NULL,&regs)==-1)
            perror("trace getregs error");
        if(ptrace(PTRACE_SYSCALL,pid,NULL,NULL)==-1)
            perror("trace continue error"); 
        
    }
  */  
    ptrace(PTRACE_DETACH,pid,NULL,NULL);

    return 0;
}
