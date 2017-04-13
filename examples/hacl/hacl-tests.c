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

#include "kremlib.h"
#include "testlib.h"
#include "Chacha20.h"
#include "Curve25519.h"
#include "Poly1305_64.h"

#include "tweetnacl.h"

#include "hacl-tests.h"


uint8_t
chacha_plaintext[114] =
    {
      (uint8_t )0x4c,
      (uint8_t )0x61,
      (uint8_t )0x64,
      (uint8_t )0x69,
      (uint8_t )0x65,
      (uint8_t )0x73,
      (uint8_t )0x20,
      (uint8_t )0x61,
      (uint8_t )0x6e,
      (uint8_t )0x64,
      (uint8_t )0x20,
      (uint8_t )0x47,
      (uint8_t )0x65,
      (uint8_t )0x6e,
      (uint8_t )0x74,
      (uint8_t )0x6c,
      (uint8_t )0x65,
      (uint8_t )0x6d,
      (uint8_t )0x65,
      (uint8_t )0x6e,
      (uint8_t )0x20,
      (uint8_t )0x6f,
      (uint8_t )0x66,
      (uint8_t )0x20,
      (uint8_t )0x74,
      (uint8_t )0x68,
      (uint8_t )0x65,
      (uint8_t )0x20,
      (uint8_t )0x63,
      (uint8_t )0x6c,
      (uint8_t )0x61,
      (uint8_t )0x73,
      (uint8_t )0x73,
      (uint8_t )0x20,
      (uint8_t )0x6f,
      (uint8_t )0x66,
      (uint8_t )0x20,
      (uint8_t )0x27,
      (uint8_t )0x39,
      (uint8_t )0x39,
      (uint8_t )0x3a,
      (uint8_t )0x20,
      (uint8_t )0x49,
      (uint8_t )0x66,
      (uint8_t )0x20,
      (uint8_t )0x49,
      (uint8_t )0x20,
      (uint8_t )0x63,
      (uint8_t )0x6f,
      (uint8_t )0x75,
      (uint8_t )0x6c,
      (uint8_t )0x64,
      (uint8_t )0x20,
      (uint8_t )0x6f,
      (uint8_t )0x66,
      (uint8_t )0x66,
      (uint8_t )0x65,
      (uint8_t )0x72,
      (uint8_t )0x20,
      (uint8_t )0x79,
      (uint8_t )0x6f,
      (uint8_t )0x75,
      (uint8_t )0x20,
      (uint8_t )0x6f,
      (uint8_t )0x6e,
      (uint8_t )0x6c,
      (uint8_t )0x79,
      (uint8_t )0x20,
      (uint8_t )0x6f,
      (uint8_t )0x6e,
      (uint8_t )0x65,
      (uint8_t )0x20,
      (uint8_t )0x74,
      (uint8_t )0x69,
      (uint8_t )0x70,
      (uint8_t )0x20,
      (uint8_t )0x66,
      (uint8_t )0x6f,
      (uint8_t )0x72,
      (uint8_t )0x20,
      (uint8_t )0x74,
      (uint8_t )0x68,
      (uint8_t )0x65,
      (uint8_t )0x20,
      (uint8_t )0x66,
      (uint8_t )0x75,
      (uint8_t )0x74,
      (uint8_t )0x75,
      (uint8_t )0x72,
      (uint8_t )0x65,
      (uint8_t )0x2c,
      (uint8_t )0x20,
      (uint8_t )0x73,
      (uint8_t )0x75,
      (uint8_t )0x6e,
      (uint8_t )0x73,
      (uint8_t )0x63,
      (uint8_t )0x72,
      (uint8_t )0x65,
      (uint8_t )0x65,
      (uint8_t )0x6e,
      (uint8_t )0x20,
      (uint8_t )0x77,
      (uint8_t )0x6f,
      (uint8_t )0x75,
      (uint8_t )0x6c,
      (uint8_t )0x64,
      (uint8_t )0x20,
      (uint8_t )0x62,
      (uint8_t )0x65,
      (uint8_t )0x20,
      (uint8_t )0x69,
      (uint8_t )0x74,
      (uint8_t )0x2e
    };

uint8_t
chacha_expected[114] =
    {
      (uint8_t )0x6e,
      (uint8_t )0x2e,
      (uint8_t )0x35,
      (uint8_t )0x9a,
      (uint8_t )0x25,
      (uint8_t )0x68,
      (uint8_t )0xf9,
      (uint8_t )0x80,
      (uint8_t )0x41,
      (uint8_t )0xba,
      (uint8_t )0x07,
      (uint8_t )0x28,
      (uint8_t )0xdd,
      (uint8_t )0x0d,
      (uint8_t )0x69,
      (uint8_t )0x81,
      (uint8_t )0xe9,
      (uint8_t )0x7e,
      (uint8_t )0x7a,
      (uint8_t )0xec,
      (uint8_t )0x1d,
      (uint8_t )0x43,
      (uint8_t )0x60,
      (uint8_t )0xc2,
      (uint8_t )0x0a,
      (uint8_t )0x27,
      (uint8_t )0xaf,
      (uint8_t )0xcc,
      (uint8_t )0xfd,
      (uint8_t )0x9f,
      (uint8_t )0xae,
      (uint8_t )0x0b,
      (uint8_t )0xf9,
      (uint8_t )0x1b,
      (uint8_t )0x65,
      (uint8_t )0xc5,
      (uint8_t )0x52,
      (uint8_t )0x47,
      (uint8_t )0x33,
      (uint8_t )0xab,
      (uint8_t )0x8f,
      (uint8_t )0x59,
      (uint8_t )0x3d,
      (uint8_t )0xab,
      (uint8_t )0xcd,
      (uint8_t )0x62,
      (uint8_t )0xb3,
      (uint8_t )0x57,
      (uint8_t )0x16,
      (uint8_t )0x39,
      (uint8_t )0xd6,
      (uint8_t )0x24,
      (uint8_t )0xe6,
      (uint8_t )0x51,
      (uint8_t )0x52,
      (uint8_t )0xab,
      (uint8_t )0x8f,
      (uint8_t )0x53,
      (uint8_t )0x0c,
      (uint8_t )0x35,
      (uint8_t )0x9f,
      (uint8_t )0x08,
      (uint8_t )0x61,
      (uint8_t )0xd8,
      (uint8_t )0x07,
      (uint8_t )0xca,
      (uint8_t )0x0d,
      (uint8_t )0xbf,
      (uint8_t )0x50,
      (uint8_t )0x0d,
      (uint8_t )0x6a,
      (uint8_t )0x61,
      (uint8_t )0x56,
      (uint8_t )0xa3,
      (uint8_t )0x8e,
      (uint8_t )0x08,
      (uint8_t )0x8a,
      (uint8_t )0x22,
      (uint8_t )0xb6,
      (uint8_t )0x5e,
      (uint8_t )0x52,
      (uint8_t )0xbc,
      (uint8_t )0x51,
      (uint8_t )0x4d,
      (uint8_t )0x16,
      (uint8_t )0xcc,
      (uint8_t )0xf8,
      (uint8_t )0x06,
      (uint8_t )0x81,
      (uint8_t )0x8c,
      (uint8_t )0xe9,
      (uint8_t )0x1a,
      (uint8_t )0xb7,
      (uint8_t )0x79,
      (uint8_t )0x37,
      (uint8_t )0x36,
      (uint8_t )0x5a,
      (uint8_t )0xf9,
      (uint8_t )0x0b,
      (uint8_t )0xbf,
      (uint8_t )0x74,
      (uint8_t )0xa3,
      (uint8_t )0x5b,
      (uint8_t )0xe6,
      (uint8_t )0xb4,
      (uint8_t )0x0b,
      (uint8_t )0x8e,
      (uint8_t )0xed,
      (uint8_t )0xf2,
      (uint8_t )0x78,
      (uint8_t )0x5e,
      (uint8_t )0x42,
      (uint8_t )0x87,
      (uint8_t )0x4d
    };

uint8_t
chacha_key[32] =
    {
      (uint8_t )0,
      (uint8_t )1,
      (uint8_t )2,
      (uint8_t )3,
      (uint8_t )4,
      (uint8_t )5,
      (uint8_t )6,
      (uint8_t )7,
      (uint8_t )8,
      (uint8_t )9,
      (uint8_t )10,
      (uint8_t )11,
      (uint8_t )12,
      (uint8_t )13,
      (uint8_t )14,
      (uint8_t )15,
      (uint8_t )16,
      (uint8_t )17,
      (uint8_t )18,
      (uint8_t )19,
      (uint8_t )20,
      (uint8_t )21,
      (uint8_t )22,
      (uint8_t )23,
      (uint8_t )24,
      (uint8_t )25,
      (uint8_t )26,
      (uint8_t )27,
      (uint8_t )28,
      (uint8_t )29,
      (uint8_t )30,
      (uint8_t )31
    };

uint8_t
chacha_nonce[12] =
    {
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0x4a,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0,
      (uint8_t )0
    };

  uint8_t
  curve25519_scalar1[32] =
    {
      (uint8_t )0xa5,
      (uint8_t )0x46,
      (uint8_t )0xe3,
      (uint8_t )0x6b,
      (uint8_t )0xf0,
      (uint8_t )0x52,
      (uint8_t )0x7c,
      (uint8_t )0x9d,
      (uint8_t )0x3b,
      (uint8_t )0x16,
      (uint8_t )0x15,
      (uint8_t )0x4b,
      (uint8_t )0x82,
      (uint8_t )0x46,
      (uint8_t )0x5e,
      (uint8_t )0xdd,
      (uint8_t )0x62,
      (uint8_t )0x14,
      (uint8_t )0x4c,
      (uint8_t )0x0a,
      (uint8_t )0xc1,
      (uint8_t )0xfc,
      (uint8_t )0x5a,
      (uint8_t )0x18,
      (uint8_t )0x50,
      (uint8_t )0x6a,
      (uint8_t )0x22,
      (uint8_t )0x44,
      (uint8_t )0xba,
      (uint8_t )0x44,
      (uint8_t )0x9a,
      (uint8_t )0xc4
    };
  uint8_t
  curve25519_scalar2[32] =
    {
      (uint8_t )0x4b,
      (uint8_t )0x66,
      (uint8_t )0xe9,
      (uint8_t )0xd4,
      (uint8_t )0xd1,
      (uint8_t )0xb4,
      (uint8_t )0x67,
      (uint8_t )0x3c,
      (uint8_t )0x5a,
      (uint8_t )0xd2,
      (uint8_t )0x26,
      (uint8_t )0x91,
      (uint8_t )0x95,
      (uint8_t )0x7d,
      (uint8_t )0x6a,
      (uint8_t )0xf5,
      (uint8_t )0xc1,
      (uint8_t )0x1b,
      (uint8_t )0x64,
      (uint8_t )0x21,
      (uint8_t )0xe0,
      (uint8_t )0xea,
      (uint8_t )0x01,
      (uint8_t )0xd4,
      (uint8_t )0x2c,
      (uint8_t )0xa4,
      (uint8_t )0x16,
      (uint8_t )0x9e,
      (uint8_t )0x79,
      (uint8_t )0x18,
      (uint8_t )0xba,
      (uint8_t )0x0d
    };
  uint8_t
  curve25519_input1[32] =
    {
      (uint8_t )0xe6,
      (uint8_t )0xdb,
      (uint8_t )0x68,
      (uint8_t )0x67,
      (uint8_t )0x58,
      (uint8_t )0x30,
      (uint8_t )0x30,
      (uint8_t )0xdb,
      (uint8_t )0x35,
      (uint8_t )0x94,
      (uint8_t )0xc1,
      (uint8_t )0xa4,
      (uint8_t )0x24,
      (uint8_t )0xb1,
      (uint8_t )0x5f,
      (uint8_t )0x7c,
      (uint8_t )0x72,
      (uint8_t )0x66,
      (uint8_t )0x24,
      (uint8_t )0xec,
      (uint8_t )0x26,
      (uint8_t )0xb3,
      (uint8_t )0x35,
      (uint8_t )0x3b,
      (uint8_t )0x10,
      (uint8_t )0xa9,
      (uint8_t )0x03,
      (uint8_t )0xa6,
      (uint8_t )0xd0,
      (uint8_t )0xab,
      (uint8_t )0x1c,
      (uint8_t )0x4c
    };
  uint8_t
  curve25519_input2[32] =
    {
      (uint8_t )0xe5,
      (uint8_t )0x21,
      (uint8_t )0x0f,
      (uint8_t )0x12,
      (uint8_t )0x78,
      (uint8_t )0x68,
      (uint8_t )0x11,
      (uint8_t )0xd3,
      (uint8_t )0xf4,
      (uint8_t )0xb7,
      (uint8_t )0x95,
      (uint8_t )0x9d,
      (uint8_t )0x05,
      (uint8_t )0x38,
      (uint8_t )0xae,
      (uint8_t )0x2c,
      (uint8_t )0x31,
      (uint8_t )0xdb,
      (uint8_t )0xe7,
      (uint8_t )0x10,
      (uint8_t )0x6f,
      (uint8_t )0xc0,
      (uint8_t )0x3c,
      (uint8_t )0x3e,
      (uint8_t )0xfc,
      (uint8_t )0x4c,
      (uint8_t )0xd5,
      (uint8_t )0x49,
      (uint8_t )0xc7,
      (uint8_t )0x15,
      (uint8_t )0xa4,
      (uint8_t )0x93
    };
  uint8_t
  curve25519_expected1[32] =
    {
      (uint8_t )0xc3,
      (uint8_t )0xda,
      (uint8_t )0x55,
      (uint8_t )0x37,
      (uint8_t )0x9d,
      (uint8_t )0xe9,
      (uint8_t )0xc6,
      (uint8_t )0x90,
      (uint8_t )0x8e,
      (uint8_t )0x94,
      (uint8_t )0xea,
      (uint8_t )0x4d,
      (uint8_t )0xf2,
      (uint8_t )0x8d,
      (uint8_t )0x08,
      (uint8_t )0x4f,
      (uint8_t )0x32,
      (uint8_t )0xec,
      (uint8_t )0xcf,
      (uint8_t )0x03,
      (uint8_t )0x49,
      (uint8_t )0x1c,
      (uint8_t )0x71,
      (uint8_t )0xf7,
      (uint8_t )0x54,
      (uint8_t )0xb4,
      (uint8_t )0x07,
      (uint8_t )0x55,
      (uint8_t )0x77,
      (uint8_t )0xa2,
      (uint8_t )0x85,
      (uint8_t )0x52
    };
  uint8_t
  curve25519_expected2[32] =
    {
      (uint8_t )0x95,
      (uint8_t )0xcb,
      (uint8_t )0xde,
      (uint8_t )0x94,
      (uint8_t )0x76,
      (uint8_t )0xe8,
      (uint8_t )0x90,
      (uint8_t )0x7d,
      (uint8_t )0x7a,
      (uint8_t )0xad,
      (uint8_t )0xe4,
      (uint8_t )0x5c,
      (uint8_t )0xb4,
      (uint8_t )0xb8,
      (uint8_t )0x73,
      (uint8_t )0xf8,
      (uint8_t )0x8b,
      (uint8_t )0x59,
      (uint8_t )0x5a,
      (uint8_t )0x68,
      (uint8_t )0x79,
      (uint8_t )0x9f,
      (uint8_t )0xa1,
      (uint8_t )0x52,
      (uint8_t )0xe6,
      (uint8_t )0xf8,
      (uint8_t )0xf7,
      (uint8_t )0x64,
      (uint8_t )0x7a,
      (uint8_t )0xac,
      (uint8_t )0x79,
      (uint8_t )0x57
    };

uint8_t
plaintext[34] =
    {
      (uint8_t )0x43,
      (uint8_t )0x72,
      (uint8_t )0x79,
      (uint8_t )0x70,
      (uint8_t )0x74,
      (uint8_t )0x6f,
      (uint8_t )0x67,
      (uint8_t )0x72,
      (uint8_t )0x61,
      (uint8_t )0x70,
      (uint8_t )0x68,
      (uint8_t )0x69,
      (uint8_t )0x63,
      (uint8_t )0x20,
      (uint8_t )0x46,
      (uint8_t )0x6f,
      (uint8_t )0x72,
      (uint8_t )0x75,
      (uint8_t )0x6d,
      (uint8_t )0x20,
      (uint8_t )0x52,
      (uint8_t )0x65,
      (uint8_t )0x73,
      (uint8_t )0x65,
      (uint8_t )0x61,
      (uint8_t )0x72,
      (uint8_t )0x63,
      (uint8_t )0x68,
      (uint8_t )0x20,
      (uint8_t )0x47,
      (uint8_t )0x72,
      (uint8_t )0x6f,
      (uint8_t )0x75,
      (uint8_t )0x70
    };
uint8_t
poly_expected[16] =
    {
      (uint8_t )0xa8,
      (uint8_t )0x06,
      (uint8_t )0x1d,
      (uint8_t )0xc1,
      (uint8_t )0x30,
      (uint8_t )0x51,
      (uint8_t )0x36,
      (uint8_t )0xc6,
      (uint8_t )0xc2,
      (uint8_t )0x2b,
      (uint8_t )0x8b,
      (uint8_t )0xaf,
      (uint8_t )0x0c,
      (uint8_t )0x01,
      (uint8_t )0x27,
      (uint8_t )0xa9
    };

uint8_t
poly_key[32] =
    {
      (uint8_t )0x85,
      (uint8_t )0xd6,
      (uint8_t )0xbe,
      (uint8_t )0x78,
      (uint8_t )0x57,
      (uint8_t )0x55,
      (uint8_t )0x6d,
      (uint8_t )0x33,
      (uint8_t )0x7f,
      (uint8_t )0x44,
      (uint8_t )0x52,
      (uint8_t )0xfe,
      (uint8_t )0x42,
      (uint8_t )0xd5,
      (uint8_t )0x06,
      (uint8_t )0xa8,
      (uint8_t )0x01,
      (uint8_t )0x03,
      (uint8_t )0x80,
      (uint8_t )0x8a,
      (uint8_t )0xfb,
      (uint8_t )0x0d,
      (uint8_t )0xb2,
      (uint8_t )0xfd,
      (uint8_t )0x4a,
      (uint8_t )0xbf,
      (uint8_t )0xf6,
      (uint8_t )0xaf,
      (uint8_t )0x41,
      (uint8_t )0x49,
      (uint8_t )0xf5,
      (uint8_t )0x1b
    };


void print_results(char *txt, double t1, int rounds, int plainlen){
  printf("Testing: %s\n", txt);
  printf("User time for %d times %d bytes: %f (%fus/byte)\n", rounds, plainlen, t1/CLOCKS_PER_SEC, (double)t1*1000000/CLOCKS_PER_SEC/plainlen/rounds);
}

int32_t test_chacha(void)
{
  uint32_t len = (uint32_t )114;
  uint8_t ciphertext[len];
  memset(ciphertext, 0, len * sizeof ciphertext[0]);
  uint32_t counter = (uint32_t )1;

  Chacha20_chacha20(ciphertext, chacha_plaintext, len, chacha_key, chacha_nonce, counter);
  TestLib_compare_and_print("HACL Chacha20", chacha_expected, ciphertext, len);

  /* crypto_stream_chacha20_ietf_xor_ic(ciphertext, chacha_plaintext, len, chacha_nonce, 1, chacha_key); */
  /* TestLib_compare_and_print("TweetNaCl Chacha20", chacha_expected, ciphertext, len); */

  return exit_success;
}

int32_t perf_chacha(void) {
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

  // HaCl
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    Chacha20_chacha20(plain, plain, len, chacha_key, chacha_nonce, counter);
    plain[0] = cipher[0];
  }
  t2 = clock();
  print_results("HACL ChaCha20 speed", (double)t2-t1, ROUNDS, CHACHA_PLAINLEN);

  /* // TweetNaCl */
  /* t1 = clock(); */
  /* for (int i = 0; i < ROUNDS; i++){ */
  /*   crypto_stream_chacha20_ietf_xor_ic(plain, plain, len, chacha_key, chacha_nonce, counter); */
  /*   plain[0] = cipher[0]; */
  /* } */
  /* t2 = clock(); */

  /* print_results("TweetNaCl ChaCha20 speed", (double)t2-t1, ROUNDS, CHACHA_PLAINLEN); */


  return exit_success;
}

int32_t test_curve(void)
{
  uint32_t keysize = (uint32_t )32;
  uint8_t result[keysize];
  memset(result, 0, keysize * sizeof result[0]);

  Curve25519_crypto_scalarmult(result, curve25519_scalar1, curve25519_input1);
  TestLib_compare_and_print("HACL Curve25519", curve25519_expected1, result, keysize);

  tweet_crypto_scalarmult(result, curve25519_scalar2, curve25519_input2);
  TestLib_compare_and_print("TweetNaCl Curve25519", curve25519_expected2, result, keysize);

  return exit_success;
}

int32_t perf_curve(void) {
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

  // HaCl
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    Curve25519_crypto_scalarmult(mul + CURVE25519_KEYSIZE * i, sk + CURVE25519_KEYSIZE * i, pk + CURVE25519_KEYSIZE * i);
  }
  t2 = clock();
  print_results("HACL Curve25519 speed", (double)(t2-t1)/ROUNDS, 1, 1);

  // TweetNaCl
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    tweet_crypto_scalarmult(mul + CURVE25519_KEYSIZE * i, sk + CURVE25519_KEYSIZE * i, pk + CURVE25519_KEYSIZE * i);
  }
  t2 = clock();
  print_results("TweetNaCl Curve25519 speed", (double)(t2-t1)/ROUNDS, 1, 1);

  return exit_success;
}

int32_t test_poly(void)
{
  uint32_t macsize = (uint32_t )16;
  uint8_t mac[macsize];
  memset(mac, 0, macsize * sizeof mac[0]);

  Poly1305_64_crypto_onetimeauth(mac, plaintext, 34, poly_key);
  TestLib_compare_and_print("HACL Poly1305", poly_expected, mac, macsize);

  tweet_crypto_onetimeauth(mac, plaintext, 34, poly_key);
  TestLib_compare_and_print("TweetNaCl Poly1305", poly_expected, mac, macsize);

  return exit_success;
}

int32_t perf_poly(void) {
  uint32_t len = POLY_PLAINLEN * sizeof(char);
  uint8_t* plain = malloc(len);
  int fd = open("/dev/urandom", O_RDONLY);
  uint64_t res = read(fd, plain, len);
  uint8_t* macs = malloc(ROUNDS * POLY_MACSIZE * sizeof(char));
  if (res != len) {
    printf("Error on reading, got %llu bytes\n", res);
    return 1;
  }

  clock_t t1,t2;

  // HaCl
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    printf("Round %d\n", i);
    Poly1305_64_crypto_onetimeauth(macs + POLY_MACSIZE * i, plain, len, poly_key);
  }
  t2 = clock();
  print_results("HACL Poly1305 speed", (double)t2-t1, ROUNDS, POLY_PLAINLEN);

  // TweetNaCl
  t1 = clock();
  for (int i = 0; i < ROUNDS; i++){
    printf("Round %d\n", i);
    tweet_crypto_onetimeauth(macs + POLY_MACSIZE * i, plain, len, poly_key);
  }
  t2 = clock();
  print_results("TweetNaCl Poly1305 speed", (double)t2-t1, ROUNDS, POLY_PLAINLEN);

  return exit_success;
}
