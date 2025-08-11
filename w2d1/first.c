#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char password[16];
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
