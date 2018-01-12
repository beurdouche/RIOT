#include "benchmarking_salsa20.h"

#define SALSA20_INPUT_LEN 14
#define SALSA20_KEYSIZE 32
#define SALSA20_NONCESIZE 12

int benchmarking_salsa20(void) {

    /* Initialize */
    xtimer_ticks64_t start_ticks0, start_ticks1;
    xtimer_ticks64_t end_ticks0, end_ticks1;
    uint64_t ticks_dif0, ticks_dif1;
    char ticks_buf0[32];
    char ticks_buf1[32];

    /*
     * Preparing
     */

    unsigned char *salsa20_ciphertext = malloc(SALSA20_INPUT_LEN * sizeof(char));
    if (salsa20_ciphertext == NULL) {
        printf("\nCould not allocate enough memory.\n\n");
        return 0;
    }
    unsigned char *salsa20_plaintext = malloc(SALSA20_INPUT_LEN * sizeof(char));
    if (salsa20_plaintext == NULL) {
        printf("\nCould not allocate enough memory.\n\n");
        return 0;
    }
    unsigned char *salsa20_nonce = malloc(SALSA20_NONCESIZE * sizeof(char));
    if (salsa20_nonce == NULL) {
        printf("\nCould not allocate enough memory.\n\n");
        return 0;
    }
    unsigned char *salsa20_key = malloc(SALSA20_KEYSIZE * sizeof(char));
    if (salsa20_key == NULL) {
        printf("\nCould not allocate enough memory.\n\n");
        return 0;
    }

    /*
     * Benchmark for HACL*
     */

    printf("Starting benchmark for HACL*\n");

    start_ticks0 = xtimer_now64();
    for (int i = 0; i < ROUNDS_CHACHA20; i++) {
        Hacl_Salsa20_salsa20(salsa20_ciphertext, salsa20_plaintext, SALSA20_INPUT_LEN, salsa20_key, salsa20_nonce, 1);
    }
    end_ticks0 = xtimer_now64();
    ticks_dif0 = (uint64_t) (end_ticks0.ticks64 - start_ticks0.ticks64);
    get_floatstring(ticks_buf0, 32, ROUNDS_CHACHA20, ticks_dif0, 8, 5, 1);

    printf("Stopping benchmark for HACL*\n");

    /*
     * Benchmark for TweetNaCl
     */

    printf("Starting benchmark for TweetNaCl\n");

    start_ticks1 = xtimer_now64();
    for (int i = 0; i < ROUNDS_CHACHA20; i++) {
        crypto_stream_salsa20_tweet_xor(salsa20_ciphertext, salsa20_plaintext, SALSA20_INPUT_LEN, salsa20_nonce, salsa20_key);
    }
    end_ticks1 = xtimer_now64();
    ticks_dif1 = (uint64_t) (end_ticks1.ticks64 - start_ticks1.ticks64);
    get_floatstring(ticks_buf1, 32, ROUNDS_CHACHA20, ticks_dif1, 8, 5, 1);

    printf("Stopping benchmark for TweetNaCl\n");

    /*
     * Display results
     */
    printf("HACL*     Salsa20: %d operations in %u ticks (%s operations per tick).\n", ROUNDS_CHACHA20, (unsigned int) ticks_dif0, ticks_buf0);
    printf("TweetNaCl Salsa20: %d operations in %u ticks (%s operations per tick).\n", ROUNDS_CHACHA20, (unsigned int) ticks_dif1, ticks_buf1);

  return 0;
}
