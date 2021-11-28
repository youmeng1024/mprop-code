#include <stdio.h>
#include <sys/unistd.h>
#include <string.h>
#include <stdlib.h>

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
     // printf("+++++++++++++++++**\n");
      // printf("addr :%lx",&strcmp);
      injectFunc();
    }
    return 0;
}
