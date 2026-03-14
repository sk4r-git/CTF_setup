#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv){
    srand(atoi(argv[1]));
    for(int i = 0; i < atoi(argv[2]); i++){
        printf("%d\n", rand());
    }
}