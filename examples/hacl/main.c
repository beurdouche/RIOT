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

#include "benchmarking_utils.h"
#include "benchmarking_curve25519.h"
#include "benchmarking_salsa20.h"

int main(void){

  /* Waiting for the user to log in the device :) */
  xtimer_sleep(10);

  /* Running the experiments */
  benchmarking_salsa20();
  benchmarking_curve25519();

  return 0;
}
