#include <stdio.h>

int main(){
  int numberone,numbertwo,answer;
  printf("Enter the first number: ");
  scanf("%d",&numberone);

  printf("Enter the second number: ");
  scanf("%d",&numbertwo);

  answer = numberone + numbertwo;
  printf("The answer is %d\n",answer);
  return 0;
}
