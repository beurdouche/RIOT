/*
 * Copyright (C) 2017 INRIA
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       HaCl* application
 *
 * @author      Benjamin Beurdouche <benjamin.beurdouche@inria.fr>
 *
 * @}
 */

#include <stdio.h>
#include "hacl-tests.h"


void print_results(char *txt, double t1, int rounds, int plainlen){
  printf("Testing: %s\n", txt);
  printf("User time for %d times %d bytes: %f (%fus/byte)\n", rounds, plainlen, t1/CLOCKS_PER_SEC, (double)t1*1000000/CLOCKS_PER_SEC/plainlen/rounds);
}

int32_t test_chacha()
{
  uint32_t len = (uint32_t )114;
  uint8_t ciphertext[len];
  memset(ciphertext, 0, len * sizeof ciphertext[0]);
  uint32_t counter = (uint32_t )1;

  Chacha20_chacha20(ciphertext, chacha_plaintext, len, chacha_key, chacha_nonce, counter);
  TestLib_compare_and_print("HACL Chacha20", chacha_expected, ciphertext, len);

  /* crypto_stream_chacha20_ietf_xor_ic(ciphertext,plaintext, len, nonce, 1, key); */
  /* TestLib_compare_and_print("Sodium Chacha20", expected, ciphertext, len); */

  return exit_success;
}

int32_t perf_chacha() {
  uint32_t len = CHACHA_PLAINLEN * sizeof(char);
  uint8_t* plain = malloc(len);
  uint8_t* cipher = malloc(len);

  int fd = open("/dev/urandom", O_RDONLY);
  uint64_t res = read(fd, plain, len);
  if (res != len) {
    printf("Error on reading, got %llu bytes\n", res);
    return 1;
  }

  uint32_t counter = (uint32_t )1;
  clock_t t1,t2;

  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    Chacha20_chacha20(plain,plain, len, chacha_key, chacha_nonce, counter);
    plain[0] = cipher[0];
  }
  t2 = clock();

  print_results("HACL ChaCha20 speed", (double)t2-t1, ROUNDS, CHACHA_PLAINLEN);

  return exit_success;
}

int32_t test_curve()
{
  uint32_t keysize = (uint32_t )32;
  uint8_t result[keysize];
  memset(result, 0, keysize * sizeof result[0]);

  Curve25519_crypto_scalarmult(result, curve25519_scalar1, curve25519_input1);
  TestLib_compare_and_print("HACL Curve25519", curve25519_expected1, result, keysize);

  Curve25519_crypto_scalarmult(result, curve25519_scalar2, curve25519_input2);
  TestLib_compare_and_print("HACL Curve25519", curve25519_expected2, result, keysize);

  return exit_success;
}

int32_t perf_curve() {
  uint32_t len = CURVE25519_KEYSIZE * ROUNDS * sizeof(char);

  unsigned char *pk, *sk, *mul;

  pk = malloc(CURVE25519_KEYSIZE * ROUNDS * sizeof(char));
  sk = malloc(CURVE25519_KEYSIZE * ROUNDS * sizeof(char));
  mul = malloc(CURVE25519_KEYSIZE * ROUNDS * sizeof(char));

  int fd = open("/dev/urandom", O_RDONLY);
  uint64_t res = read(fd, sk, len);
  if (res != len) {
    printf("Error on reading, got %llu bytes\n", res);
    return 1;
  }
  res = read(fd, pk, len);
  if (res != len) {
    printf("Error on reading, got %llu bytes\n", res);
    return 1;
  }

  clock_t t1,t2;
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    Curve25519_crypto_scalarmult(mul + CURVE25519_KEYSIZE * i, sk + CURVE25519_KEYSIZE * i, pk + CURVE25519_KEYSIZE * i);
  }
  t2 = clock();
  print_results("HACL Curve25519 speed", (double)(t2-t1)/ROUNDS, 1, 1);

  return exit_success;
}

int32_t test_poly()
{
  uint32_t macsize = (uint32_t )16;
  uint8_t mac[macsize];
  memset(mac, 0, macsize * sizeof mac[0]);
  Poly1305_64_crypto_onetimeauth(mac, plaintext, 34, poly_key);
  TestLib_compare_and_print("HACL Poly1305", poly_expected, mac, macsize);
  return exit_success;
}

int32_t perf_poly() {
  uint32_t len = POLY_PLAINLEN * sizeof(char);
  uint8_t* plain = malloc(len);
  int fd = open("/dev/urandom", O_RDONLY);
  uint64_t res = read(fd, plain, len);
  uint8_t* macs = malloc(ROUNDS * POLY_MACSIZE * sizeof(char));
  if (res != len) {
    printf("Error on reading, got %llu bytes\n", res);
    return 1;
  }

  printf("Before timing\n");

  clock_t t1,t2;
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    printf("Round %d\n", i);
    Poly1305_64_crypto_onetimeauth(macs + POLY_MACSIZE * i, plain, len, poly_key);
  }
  t2 = clock();
  print_results("HACL Poly1305 speed", (double)t2-t1, ROUNDS, POLY_PLAINLEN);

  return exit_success;
}
