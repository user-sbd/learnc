#include <stdio.h>

void rev(char *str) {
    if (str == NULL) return;
    int length = 0;
    while (str[length] != '\0') {
        length++;
    }
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
    printf("Reversed string: %s\n", str);
}

int main(){
  char str[100];
  printf("Enter a string: ");
	scanf("%s", str);
	rev(str);
  return 0;
}
