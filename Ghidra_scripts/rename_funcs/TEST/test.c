#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int f(int a){
    return a*4;
}

int g(int a){
    return a*5;
}

int main(int argc, char ** argv){
    int a = 5;
    int c = f(a);
    int d = g(a);
    return c*d;
}
