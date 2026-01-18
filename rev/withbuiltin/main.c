#include <stdio.h>
#include <string.h>

void rev(char*s){
	int l = 0;
	int r = strlen(s) - 1;
	char t;
	while (l<r){
		t = s[l];
		s[l] = s[r];
		s[r] = t;
	}
	l++;
	r--;

	printf("%s", s);
}

int main(){
	char s[100];
	char str[100];
	printf("Enter a string to reverse: ");
	scanf("%s", s);
	strcpy(s, str);
}
