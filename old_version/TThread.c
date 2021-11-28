#include <stdio.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>
int main(){
    int i;
    for(i = 0;i < 100; ++i) {
        printf("My counter: %d\n", i);
        sleep(2);
        i=1;
     }

    return 0;
}
