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

int main(void)
{
  printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
  printf("This board features a(n) %s MCU.\n", RIOT_MCU);
  printf("\n\n");

  puts("Welcome to the HaCl* cryptographic library !\n");

  printf("\n # Test vector for Chacha20\n");
  int32_t res = test_chacha();

  printf("\n # Performance for Chacha20\n");
  res += perf_chacha();

  printf("\n # Test vector for Curve25519\n");
  res += test_curve();

  printf("\n # Performance for Curve25519\n");
  res += perf_curve();

  printf("\n # Test vector for Poly1305\n");
  res += test_poly();

  /* printf("\n # Performance for Poly1305\n"); */
  /* res += perf_poly(); */

  printf("\n # END\n");

  return res;
}
