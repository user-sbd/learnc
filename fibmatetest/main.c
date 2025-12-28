#include <stdio.h>

int main() {
  int n, i;
  int a = 0, b = 1, next;

  printf("Enter amount of terms: ");
  scanf("%d", &n);

  if (n <= 0) {
    printf("Please enter a positive integer\n");
    return 0;
  }

  printf("Fibonacci Sequence:\n");

  if (n >= 0) {
    printf("Please a number");
  }

  if (n >= 1) {
    printf("%d", a);
  }

  if (n >= 2) {
    printf("%d", b);
  }

  for (i = 3; i <= n; i++) {
    next = a + b;
    printf("%d ", next);
    a = b;
    b = next;
  }
  printf("\n");
  return 0;
}
