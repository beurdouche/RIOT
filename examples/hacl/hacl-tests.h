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

#ifndef __Hacl_Tests_H
#define __Hacl_Tests_H

#include <stdio.h>
#include "kremlib.h"
#include "testlib.h"
#include "Chacha20.h"
#include "Curve25519.h"
#include "Poly1305_64.h"

#include "tweetnacl.h"


void print_results(char *txt, double t1, int rounds, int plainlen);

#define ROUNDS 1000

#define CHACHA_PLAINLEN (16*1024)
#define CHACHA_MACSIZE 32

#define CURVE25519_KEYSIZE 32

#define POLY_PLAINLEN (1024*1024)
#define POLY_MACSIZE 32

int32_t test_chacha(void);
int32_t perf_chacha(void);

int32_t test_curve(void);
int32_t perf_curve(void);

int32_t test_poly(void);
int32_t perf_poly(void);

#endif
