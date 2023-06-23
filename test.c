int foo(int a, int b) {
    return a+b;
}

int main () {
    foo(3,4);
    printf("1\n");
    foo(0,0);
    printf("2\n");
    return 0;
}