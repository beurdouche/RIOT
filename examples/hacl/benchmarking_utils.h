#ifndef __Benchmarking_Utils_H
#define __Benchmarking_Utils_H

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

void get_floatstring(char* buf, size_t buf_size, int64_t dividend, int64_t divisor, uint8_t precision, uint8_t pre_precision, uint8_t round);

#endif
