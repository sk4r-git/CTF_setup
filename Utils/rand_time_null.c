#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char ** argv){
    srand(time(NULL));
    for(int i = 0; i < atoi(argv[1]); i++){
        printf("%d\n", rand());
    }
}