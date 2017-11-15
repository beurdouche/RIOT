#ifndef __Benchmarking_Curve25519_H
#define __Benchmarking_Curve25519_H

#include "xtimer.h"
#include "timex.h"
#include "random.h"

#include "benchmarking_utils.h"
#include "Curve25519.h"
#include "tweetnacl.h"

#define ROUNDS 10

int benchmarking_curve25519(void);

#endif
