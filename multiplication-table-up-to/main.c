#include <stdio.h>

int main() {
    int num, i, inc;
    printf("Enter number for multiplication table: ");
    scanf("%d", &num);
    printf("How far do you want this table to go: ");
    scanf("%d", &inc);
    for (i = 1; i <= inc; i++) {
        printf("%d × %d = %d\n", num, i, num * i);
    }
    return 0;
}
