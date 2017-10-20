/*
 * Copyright (C) 2017 INRIA, Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/*
 * Based on example from Adrian Herrmann <adrian.herrmann@fu-berlin.de>
 * https://github.com/adrianghc/RIOT/edit/master/examples/hashing/main.c
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       HACL* application
 *
 * @author      Benjamin Beurdouche <benjamin.beurdouche@inria.fr>
 *
 * @}
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

#include "xtimer.h"
#include "timex.h"
#include "random.h"
#include "Curve25519.h"

/*
 * Function to generate a string with the result of a division without using floating point arithmetic.
 * The string is cut off at a given precision after the decimal point. If applicable and configured, the last digit is rounded up.
 *
 * @param[out]  buf             Pointer to the buffer for the string to be generated.
 * @param[in]   buf_size        The size of the buffer.
 * @param[in]   dividend        The dividend.
 * @param[in]   divisor         The divisor.
 * @param[in]   precision       The maximum number of digits after the decimal point.
 * @param[in]   pre_precision   The maximum numer of digits before the decimal point.
 *                              Exception: When a number only containing the digit 9 is rounded up.
 * @param[in]   round           0 if the last digit is to be rounded up if applicable,
 *                              1 otherwise.
 */
void get_floatstring(char* buf, size_t buf_size, int64_t dividend, int64_t divisor, uint8_t precision, uint8_t pre_precision, uint8_t round) {

    /* Initialize */
    uint8_t i = 0;
    uint8_t inc_i = 0;
    uint8_t buf_init = 0;
    uint8_t is_negative = 0;
    size_t len = 0;
    int64_t quot;
    char quot_chars[pre_precision+1];

    /* Handle divisor 0 */
    if (divisor == 0) {
        return;
    }

    /* Handle dividend 0 */
    if (dividend == 0) {
        strcpy(buf, "0");
        return;
    }

    /* Handle negative input */
    if ((dividend < 0 && divisor > 0) || (divisor < 0 && dividend > 0)) {
        is_negative = 1;
        dividend = llabs(dividend);
        divisor = llabs(divisor);
        strcpy(buf, "-");
        buf_init = 1;
        len += 1;
    }

    /* Generate the string */
    while (i<precision+1 && len<buf_size-1) {
        if (dividend < divisor) {
            if (!inc_i) {
                inc_i = 1;
                if (!is_negative && !buf_init) {
                    strcpy(buf, "0");
                    buf_init = 1;
                    len += 1;
                }
                else if (is_negative && buf[len-1] == '-') {
                    strncat(buf, "0", 1);
                    len += 1;
                }
                strncat(buf, ".", 1);
                len += 1;
            }
            dividend *= 10;
        }
        if (i == precision || len == buf_size-1) {
            if (buf[len-1] == '.') {
                buf[len-1] = '\0';
            }
            break;
        }
        quot = dividend / divisor;
        snprintf(quot_chars, pre_precision+1, "%d", (int) quot);
        if (i == 0 && !inc_i && !buf_init) {
            strcpy(buf, quot_chars);
            buf_init = 1;
        } else {
            strncat(buf, quot_chars, pre_precision+1);
        }
        len += strlen(quot_chars);
        dividend -= divisor * quot;
        if (inc_i) {
            i++;
        }
    }
    if (len == buf_size-1 && dividend < divisor) {
        dividend *= 10;
    }
    buf[len] = '\0';

    /* End here if rounding is not desired */
    if (!round) {
        return;
    }

    /* Do the rounding */
    quot = dividend / divisor;
    if (quot >= 5) {
        for (int j=len-1; j>=0; j--) {
            if (buf[j] == '.' || buf[j] == '-') {
                continue;
            }
            if (buf[j] >= '9') {
                buf[j] = '0';
            } else {
                buf[j]++;
                break;
            }
        }
        /* Special case if a number that was rounded up only contained the digit 9 */
        if ((!is_negative && buf[0] == '0' && buf[1] == '0') || (is_negative && buf[1] == '0' && buf[2] == '0')) {
            for (size_t k=len-1; k>0; k--) {
                buf[k] = buf[k-1];
            }
            if (!is_negative) {
                buf[0] = '1';
            } else {
                buf[1] = '1';
            }
            buf[len] = '\0';
            if (buf[len-1] == '.') {
                buf[len-1] = '\0';
            }
        }
    }
}

#define KEYSIZE 32
#define ROUNDS 1000

int main(void) {

  /* Initialize */
  xtimer_ticks64_t start_ticks;
  xtimer_ticks64_t end_ticks;
  uint64_t ticks_dif;
  char ticks_buf[32];

  /* Generate inputs */
  random_init(0x33799f);

  unsigned char *pk = malloc(KEYSIZE * ROUNDS * sizeof(char));
  if (pk == NULL) {
      printf("\nCould not allocate enough memory.\n\n");
      return 0;
  }
  unsigned char *sk = malloc(KEYSIZE * ROUNDS * sizeof(char));
  if (sk == NULL) {
      printf("\nCould not allocate enough memory.\n\n");
      return 0;
  }
  unsigned char *mul = malloc(KEYSIZE * ROUNDS * sizeof(char));
  if (mul == NULL) {
      printf("\nCould not allocate enough memory.\n\n");
      return 0;
  }

  //
  // Benchmark for HACL*
  //

  start_ticks = xtimer_now64();
  for (int i = 0; i < ROUNDS; i++){
    Curve25519_crypto_scalarmult(mul + KEYSIZE * i, sk + KEYSIZE * i, pk + KEYSIZE * i);
  }
  end_ticks = xtimer_now64();
  ticks_dif = (uint64_t) (end_ticks.ticks64 - start_ticks.ticks64);
  get_floatstring(ticks_buf, 32, ROUNDS, ticks_dif, 8, 5, 1);
  printf("HACL* Curve25519: %d operations in %u ticks (%s operations per tick).\n\n", ROUNDS, (unsigned int) ticks_dif, ticks_buf);

  return 0;
}

