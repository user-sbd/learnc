#include <stdio.h>

int main(){
	int num;
	printf("number to check even or odd: ");
	scanf("%d", &num);
	if (num % 2 == 0)	{
		printf("%d is odd\n",num);
	} else {
		printf("%d is even\n",num);
	}
}

