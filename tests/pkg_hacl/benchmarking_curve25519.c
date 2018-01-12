#include "benchmarking_curve25519.h"

#define CURVE25519_POINTSIZE 32

int benchmarking_curve25519(void) {

  /* Initialize */
  xtimer_ticks64_t start_ticks0,start_ticks1;
  xtimer_ticks64_t end_ticks0,end_ticks1;
  uint64_t ticks_dif0,ticks_dif1;
  char ticks_buf0[32];
  char ticks_buf1[32];

  //
  // Preparing
  //

  unsigned char *curve25519_public = malloc(CURVE25519_POINTSIZE * sizeof(char));
  if (curve25519_public == NULL) {
      printf("\nCould not allocate enough memory.\n\n");
      return 0;
  }
  unsigned char *curve25519_secret = malloc(CURVE25519_POINTSIZE * sizeof(char));
  if (curve25519_public == NULL) {
      printf("\nCould not allocate enough memory.\n\n");
      return 0;
  }
  unsigned char *curve25519_basepoint = malloc(CURVE25519_POINTSIZE * sizeof(char));
  if (curve25519_basepoint == NULL) {
      printf("\nCould not allocate enough memory.\n\n");
      return 0;
  }

  //
  // Benchmark for HACL*
  //

  printf("Starting benchmark for HACL*\n");

  start_ticks0 = xtimer_now64();
  for (int i = 0; i < ROUNDS_CURVE25519; i++) {
    Hacl_Curve25519_crypto_scalarmult(curve25519_public,curve25519_secret,curve25519_basepoint);
  }
  end_ticks0 = xtimer_now64();
  ticks_dif0 = (uint64_t) (end_ticks0.ticks64 - start_ticks0.ticks64);
  get_floatstring(ticks_buf0, 32, ROUNDS_CURVE25519, ticks_dif0, 8, 5, 1);

  printf("Stopping benchmark for HACL*\n");

  //
  // Benchmark for TweetNaCl
  //

  printf("Starting benchmark for TweetNaCl\n");

  start_ticks1 = xtimer_now64();
  for (int i = 0; i < ROUNDS_CURVE25519; i++) {
    crypto_scalarmult(curve25519_public,curve25519_secret,curve25519_basepoint);
  }
  end_ticks1 = xtimer_now64();
  ticks_dif1 = (uint64_t) (end_ticks1.ticks64 - start_ticks1.ticks64);
  get_floatstring(ticks_buf1, 32, ROUNDS_CURVE25519, ticks_dif1, 8, 5, 1);

  printf("Stopping benchmark for TweetNaCl\n");

  //
  // Display results
  //
  printf("HACL*     Curve25519: %d operations in %u ticks (%s operations per tick).\n", ROUNDS_CURVE25519, (unsigned int) ticks_dif0, ticks_buf0);
  printf("TweetNaCl Curve25519: %d operations in %u ticks (%s operations per tick).\n", ROUNDS_CURVE25519, (unsigned int) ticks_dif1, ticks_buf1);

  return 0;
}
