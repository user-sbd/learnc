#include <stdio.h>

int main() {
  int first, second;
  printf("Enter the first digit: ");
  scanf("%d", &first);
  printf("Enter the second digit: ");
  scanf("%d", &second);
  if (first > second) {
    printf("%d is the smallest number\n", second);
  } else {
    printf("%d is the smallest number\n", first);
  }
}
