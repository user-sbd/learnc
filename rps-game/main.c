#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int main() {
    char player_move[20];
    char *computer_moves[] = {"rock", "paper", "scissors"};
    
    srand(time(NULL));
    int random_index = rand() % 3;
    char *computer_move = computer_moves[random_index];

    printf("Enter rock, paper, or scissors: ");
    fgets(player_move, sizeof(player_move), stdin);

    player_move[strcspn(player_move, "\n")] = '\0';

    printf("You chose: %s\n", player_move);
    printf("Computer chose: %s\n", computer_move);

    if (strcmp(player_move, computer_move) == 0) {
        printf("It's a tie!\n");
    }
    else if ((strcmp(player_move, "rock") == 0 && strcmp(computer_move, "scissors") == 0) ||
             (strcmp(player_move, "paper") == 0 && strcmp(computer_move, "rock") == 0) ||
             (strcmp(player_move, "scissors") == 0 && strcmp(computer_move, "paper") == 0)) {
        printf("You win!\n");
    }
    else if (strcmp(player_move, "rock") != 0 && 
             strcmp(player_move, "paper") != 0 && 
             strcmp(player_move, "scissors") != 0) {
        printf("Invalid input! Please type rock, paper, or scissors in lowercase.\n");
    }
    else {
        printf("Computer wins!\n");
    }

    return 0;
}

