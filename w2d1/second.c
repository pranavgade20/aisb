#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void admin_access() {
    printf("\n[!] Admin access granted!\n");
    printf("[!] Flag: AISB{woo!}\n\n");
    exit(0);
}

unsigned long simple_hash(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

void verify_user(char *password) {
    char buffer[32];
    unsigned long expected_hash = 6385045028UL;

    strcpy(buffer, password);

//    printf("\n[Debug] Hex dump of 128 binytes starting at buffer[-32]:\n");
//    printf("Address: %p\n", &buffer);
//
//    unsigned char *ptr = (unsigned char *)&buffer[-32];
//    for (int i = 0; i < 128; i++) {
//        if (i % 16 == 0) {
//            printf("\n%04x: ", i);
//        }
//        printf("%02x ", ptr[i]);
//        if (i % 16 == 15) {
//            printf(" |");
//            for (int j = i - 15; j <= i; j++) {
//                if (ptr[j] >= 32 && ptr[j] <= 126) {
//                    printf("%c", ptr[j]);
//                } else {
//                    printf(".");
//                }
//            }
//            printf("|");
//        }
//    }
//    printf("\n\n");

    // Check password hash
    unsigned long input_hash = simple_hash(buffer);

    if (input_hash == expected_hash) {
        printf("\n[+] Password correct! Authentication successful.\n");
        admin_access();
    } else {
        printf("\n[-] Invalid password. Access denied.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    printf("=== Vulnerable Application v2.0 ===\n");
    printf("This program demonstrates a buffer overflow vulnerability.\n\n");

    printf("[Debug Info]\n");
    printf("verify_user() address: %p\n", verify_user);
    printf("admin_access() address: %p\n", admin_access);

    verify_user(argv[1]);

    printf("Verification complete. Exiting...\n");

    return 0;
}
