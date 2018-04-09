PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=e046ebac8bfff344077a67aace5d971a3632f316
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp Makefile.hacl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
