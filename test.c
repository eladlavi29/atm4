int foo(int a, int b) {
    return a+b;
}

int main () {
    printf("Im suppose to be second to get here\n");
    foo(3,4);
    foo(0,0);
    return 0;
}