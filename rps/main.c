#include <stdio.h>
#include <string.h>

int main() {
  char s[20];
  printf("Enter (Rock, Paper, Scissors): ");
  scanf("%s", s);
  if (strcmp(s, "Rock") == 0) {
    printf("You won!\n");
  } else {
    printf("You lost!\n");
  }
}
