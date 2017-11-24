 # name of your application
APPLICATION = hacl

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP -DKRML_NOUINT128 -DTHREAD_STACKSIZE_MAIN=2500

USEMODULE += xtimer
USEMODULE += random

USEPKG += hacl
USEPKG += tweetnacl

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
