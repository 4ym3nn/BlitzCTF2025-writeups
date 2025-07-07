#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define THREAD_COUNT 1
#define MAX_LEN 512

unsigned char *enc_data = NULL;
size_t enc_len = 0;
int found = 0;

void rc4_encrypt(unsigned char *data, size_t len, unsigned char *out, unsigned int seed) {
    unsigned char S[256];
    unsigned char T[256];
    int i, j, t;

    for (i = 0; i < 256; i++) S[i] = i;
    srand(seed);
    for (i = 0; i < 256; i++) T[i] = (unsigned char)rand();

    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        S[i] ^= S[j]; S[j] ^= S[i]; S[i] ^= S[j];
    }

    int x = 0, y = 0;
    for (i = 0; i < len; i++) {
        x = (x + 1) % 256;
        y = (y + S[x]) % 256;
        S[x] ^= S[y]; S[y] ^= S[x]; S[x] ^= S[y];
        t = (S[x] + S[y]) % 256;
        out[i] = data[i] ^ S[t];
    }
}

void *bruteforce(unsigned int start , unsigned int end) {
    unsigned char dec[MAX_LEN];

    for (unsigned int seed = start; seed < end; seed++) {
        rc4_encrypt(enc_data, enc_len, dec, seed);
        dec[enc_len] = '\0';

        if (strncmp((char *)dec, "Blitz{", 6) == 0 || strncmp((char *)dec, "flag{", 5) == 0) {
            printf("[+] Found seed: %u (0x%x)\n", seed, seed);
            printf("[+] Decrypted: %s\n", dec);
            break;
        }

        if((seed % 100000) == 0) {
            printf("    in: %d\n",seed);
        }
    }

    return NULL;
}

int main() {
    FILE *f = fopen("flag.txt.enc", "rb");
    if (!f) {
        perror("Error opening file");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    enc_len = ftell(f);
    rewind(f);

    enc_data = malloc(enc_len);
    fread(enc_data, 1, enc_len, f);
    fclose(f);

    time_t now = time(NULL);
    time_t start_seed = now - (60 * 60 * 24 * 30 * 2); // 2 months ago
    time_t end_seed = now;

    bruteforce(start_seed,end_seed);

    return 0;
}

// Blitz{71m3_5ur3_fl0w5_f457_l1k3_4_r1v3r_50m371m35}
