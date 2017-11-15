 # name of your application
APPLICATION = hacl

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP -DKRML_NOUINT128 -Wno-error -Wno-unused-parameter -Wno-unused-function -Wno-error=unused-function -Wno-parentheses -Wno-error=parentheses -Wno-unused-variable -Wno-error=unused-variable -Wno-ignored-qualifiers -Wno-error=ignored-qualifiers -DTHREAD_STACKSIZE_MAIN=2250

USEMODULE += xtimer
USEMODULE += random

USEPKG += hacl
USEPKG += tweetnacl

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 0

include $(RIOTBASE)/Makefile.include

CFLAGS += -DDEVELHELP -DKRML_NOUINT128 -Wno-error -Wno-unused-parameter -Wno-unused-function -Wno-error=unused-function -Wno-parentheses -Wno-error=parentheses -Wno-unused-variable -Wno-error=unused-variable -Wno-ignored-qualifiers -Wno-error=ignored-qualifiers -DTHREAD_STACKSIZE_MAIN=2250
