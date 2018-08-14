#include <stdio.h>
#include <sys/unistd.h>
void injectFunc()
{
    printf("i have hook it!!!!!!!!!!\n");
    printf("this is second step!!\n");
}

int main(int argc, char *argv[])
{
    while(1)
    {
       sleep(3);
       printf("+++++++++++++++++\n");
    }
    return 0;
}
