#include <stdio.h>

int main() {
  int num, count = 0;
  printf("enter a number: ");
  scanf("%d", &num);
  for (int i = 2; i < num; i++) {
    if (num % i == 0) {
      count += 1;
			break;
    }
  }
	if ( count == 0 ){
		printf("%d is a prime number\n",num);
	} else {
		printf("%d is not a prime number\n",num);
	}
	return 0;
}

