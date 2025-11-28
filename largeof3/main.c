#include <stdio.h>

int main() {
	int one,two,three;
	printf("enter three numbers: ");
	scanf("%d %d %d", &one, &two, &three);
	if ( one > two && one > three){
		printf("%d is the largest number\n", one);
	}
	else if (two > one && two > three) {
		printf("%d is the largest number\n", two);
	}
	else {
		printf("%d is the largest number\n", three);
	}
}
