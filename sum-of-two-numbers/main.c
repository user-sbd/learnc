#include <stdio.h>

int main() {
  int marks;
  printf("enter your marks in computer: \r");
  scanf("%d", &marks);
	if (marks > 30){
		printf("you have passed \n");
	}else {
		printf("you have failed\n");
	}
}
