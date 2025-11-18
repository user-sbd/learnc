// calculator in c
// date nov 17 2025
// by: nitin subedi

#include <stdio.h>
#include <math.h>

int main() {

  // declare varibles
  float num1, num2, ans;
  char operator;
  char line[100];

  printf("calc by Nitin\n");
  printf("enter expression: ");
  fgets(line, sizeof(line), stdin);
  // printf("%s", line);
  sscanf(line, "%f %c %f", &num1, &operator, &num2);
  // printf("%f\n", num1);
  // printf("%c\n", operator);
  // printf("%f\n", num2);

  switch (operator) {
  case '+':
    ans = num1 + num2;
		printf("%.f\n", ans);
    break;
	case '-':
		ans = num1 - num2;
		printf("%.f\n", ans);
    break;
	case '*':
		ans = num1 * num2;
		printf("%.f\n", ans);
    break;
	case '/':
		ans = num1 / num2;
		printf("%.f\n", ans);
    break;
	case '^':
		ans = pow(num1, num2);
		printf("%.f\n", ans);
    break;
  default:
    printf("Operator could not be read.\n");
  };
}
