include ../Makefile.tests_common

BOARD = iotlab-m3

# Using software UInt128 operations for all platforms
# Setting the minimum stack size required for the biggest consumer in HACL*
CFLAGS +=-DKRML_NOUINT128 -DTHREAD_STACKSIZE_MAIN=2500 -Wno-error=unused-variable

USEMODULE += xtimer
USEMODULE += random

USEPKG += hacl
USEPKG += tweetnacl

include $(RIOTBASE)/Makefile.include
