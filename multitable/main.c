#include <stdio.h>

int main(){
	int num,sum,i;
	printf("Multiplcation Table Generator\n");
	printf("num: ");
	scanf("%d", &num);

	for (i = 1; i <= 10; i++) {
			sum	= i * num;
			printf("%d * %d = %d\n", num,i,sum);
	}

}
