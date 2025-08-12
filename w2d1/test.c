#include <stddef.h>
#include <stdio.h>


// void print_bytes(void *p, size_t len)
// {
//     size_t i;
//     printf("(");
//     for (i = 0; i < len; ++i)
//         printf("%02X", ((unsigned char*)p)[i]);
//     printf(")");
// }

// void print_int(int x)
// {
//     print_bytes(&x, sizeof(x));
// }

int main() {
    int authorized = 2;
    if (authorized){
        printf("Authorized is true");
    }

}
