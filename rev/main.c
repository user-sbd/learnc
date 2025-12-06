#include <stdio.h>

int revstring(const char* str){
	int length = 0;
	while (str[length] != '\0') {
		length++;
	}
	int start = 0;
	int end = length - 1;
	char temp;

	while (start < end) {
		temp = str[start];
		str[start] = str[end];
		start++;
		end--;
	}
}

int main(){
  char string[15];
  printf("Enter a string: ");
	scanf("%s", string);
  return 0;
}
