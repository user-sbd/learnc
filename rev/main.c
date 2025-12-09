#include <stdio.h>

int rev(char *str){
	int length = 0;
	
	while (str[length] != '\0'){
		length++;
	}
	int start = 0, end = length - 1;
	while (start < end){
		char temp = str[start]; 
		str[start] = str[end];
		str[end] = temp;
		printf("%s", str);
	}
	return 0;
}

int main(){
  char str[100];
  printf("Enter a string: ");
	scanf("%s", str);
  return 0;
}
