#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    // The variables are laid out in memory one after the other
    // If you input more than 16 bytes into password, you start overwriting whatever is next in memory 
    // In this case this is the authorised variables
    // password is a variable that stores 16 bytes
    char password[16];
    // If the authorised variable is a value that is not zero
    // so you overwrite it with a non-zero value, the program will think you are authenticated
    int authorized = 0;

    printf("=== Secure Login System v1.0 ===\n");
    printf("Enter the password: ");

    gets(password);
    printf("authorized: %d\n", authorized);

    if (strcmp(password, "secret123") == 0) {
        authorized = 1;
        printf("Password correct!\n");
    } else {
        printf("Wrong password.\n");
    }

    if (authorized) {
        printf("Access granted! Welcome to the secure system.\n");
        printf("Flag: AISB{woo}\n");
        return 0;
    } else {
        printf("Access denied.\n");
        return 1;
    }
}
