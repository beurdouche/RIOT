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

int main(void)
{
    puts("Welcome to the HaCl* cryptographic library !");

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);

    return 0;
}
