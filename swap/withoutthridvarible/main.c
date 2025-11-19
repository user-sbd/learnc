#include <stdio.h>

int main() {
  int first, second;
  printf("enter first: ");
  scanf("%d", &first);
  printf("enter second: ");
  scanf("%d", &second);
  printf("before swapping: a = %d, b = %d\n", first, second);
  first = first ^ second;
  second = first ^ second;
  first = first ^ second;
  printf("after swapping: a = %d, b = %d\n", first, second);
  return 0;
}
