/*
 * Copyright (C) 2018 INRIA
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @addtogroup  unittests
 * @{
 *
 * @file
 * @brief       Unittests for the ``hacl`` package
 *
 * @author      Benjamin Beurdouche <benjamin.beurdouche@inria.fr>
 */
#ifndef TESTS_HACL_H
#define TESTS_HACL_H

#include "embUnit/embUnit.h"
#include "random.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief MANDATORY function for collecting random Bytes
 *        required by the HACL* package
 */
extern void randombytes(uint8_t *target, uint64_t n);

/**
*  @brief   The entry point of this test suite.
*/
void tests_hacl(void);

/**
 * @brief   Generates tests for HACL*
 *
 * @return  embUnit tests if successful, NULL if not.
 */
Test *tests_hacl_tests(void);

#ifdef __cplusplus
}
#endif

#endif /* TESTS_HACL_H */
/** @} */
