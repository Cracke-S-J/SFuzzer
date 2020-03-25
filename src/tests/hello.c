#include <stdio.h>
int b = 9;
int add(int a, int b) {
    return a + b;
}
int sub(int a, int b) {
    return a - b;
}
int main() {
    printf("hello\n");
    int a = 0;
    for (int i = 0; i < b; ++i) {
        a = add(i, a);
        a = sub(a, i);
    }
    printf("%d: \n", a);
    return 0;
}