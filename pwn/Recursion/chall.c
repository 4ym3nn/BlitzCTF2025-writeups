//  gcc chall.c -o chall -fno-stack-protector -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    printf("You win!\n");
    system("/bin/sh");
}

int main() {
    char buf[0x100];

    ssize_t n = read(0, buf, sizeof(buf) + 0x18);
    puts(buf);

    if (buf[n - 1] != '\n')
        return main();

    return 0;
}
