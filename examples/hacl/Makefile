 # name of your application
APPLICATION = hacl

# If no BOARD is found in the environment, use this default:
BOARD ?= iotlab-m3

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

DEVELHELP ?= 1

# Using software UInt128 operations for all platforms
# Setting the minimum stack size required for the biggest consumer in HACL*
CFLAGS += -DKRML_NOUINT128 -DTHREAD_STACKSIZE_MAIN=2500

USEMODULE += xtimer
USEMODULE += random

USEPKG += hacl
USEPKG += tweetnacl

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
