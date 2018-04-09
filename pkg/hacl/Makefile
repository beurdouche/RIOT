PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=6d71239411f050920fa14d3dab329a4bf6f18823
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp Makefile.hacl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
