include ../Makefile.tests_common

CFLAGS +=-DKRML_NOUINT128 -DTHREAD_STACKSIZE_MAIN=2500

USEMODULE += xtimer
USEMODULE += random

USEPKG += hacl
USEPKG += tweetnacl

include $(RIOTBASE)/Makefile.include
