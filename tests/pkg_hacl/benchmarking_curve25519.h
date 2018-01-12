#ifndef __BENCHMARKING_CURVE25519_H
#define __BENCHMARKING_CURVE25519_H

#include "xtimer.h"
#include "timex.h"
#include "random.h"

#include "benchmarking_utils.h"
#include "Hacl_Curve25519.h"
#include "tweetnacl.h"

#define ROUNDS_CURVE25519 10

int benchmarking_curve25519(void);

#endif
