PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=40f90b6311eb9d126f77e296d30dd04f9681c1dc
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp Makefile.hacl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
