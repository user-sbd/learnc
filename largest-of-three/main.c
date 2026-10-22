#include <stdio.h>

int main() {
  int one, two, three;
  printf("Enter 3 numbers: ");
  scanf("%d %d %d", &one, &two, &three);

  if (one > two && one > three) {
    printf("%d is the greatest\n", one);
  } else if (two > one && two > three) {
    printf("%d is the greatest\n", two);
  } else {
    printf("%d is the greatest\n", three);
  }
  return 0;
}

