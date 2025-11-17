#include <stdio.h>

int main(){
	printf("simple sum program \n");

	// declare varibles
	int one,two,sum;

	// request the first num and store
	printf("enter first num: ");
  scanf("%d", &one);

	// request the second num and store
	printf("enter second num: ");
  scanf("%d", &two);
	
	// add the two nums and print the sum
	sum = one + two ;
	printf("the answer of %d and %d is %d \n",one,two,sum);
}
