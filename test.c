int foo(int a, int b) {
    if(a == 0){
        return b;
    }
    return foo(a - 1, b + 1);
}

int main () {
    foo(3, 4);
    foo(0, 0);
    return 0;
}