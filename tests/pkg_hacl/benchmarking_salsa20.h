#ifndef __Benchmarking_Salsa20_H
#define __Benchmarking_Salsa20_H

#include "xtimer.h"
#include "timex.h"
#include "random.h"

#include "benchmarking_utils.h"
#include "Hacl_Salsa20.h"
#include "tweetnacl.h"

#define ROUNDS_CHACHA20 10000

int benchmarking_salsa20(void);

#endif
