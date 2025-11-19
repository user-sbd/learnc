#include <stdio.h>

int main() {
  int first, second, swap;
  printf("enter num 1: ");
  scanf("%d", &first);
  printf("enter num 2: ");
  scanf("%d", &second);
	printf("before swapping: a = %d, b = %d\n", first, second);
  swap = first;
  first = second;
  second = swap;
	printf("After swapping: a = %d, b = %d\n", first, second);
}
