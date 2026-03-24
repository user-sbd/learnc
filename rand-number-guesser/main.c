#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
  srand(time(NULL));
  int guess;
  int attempts = 0;
  int num = rand() % 100;
  bool guessed = false;

  while (!guessed) {
    printf("Enter the guess: ");
    scanf("%d", &guess);
    attempts++; 
    if(guess>num) {
      printf("The number is lower\n");
    }
    else if (guess<num){
      printf("The number is higher\n");
    }
    else {
      printf("You are right!\n You completed in %d attempts\n", attempts);
      guessed = true; // This is how you set the boolean after declaring
    }
} }
