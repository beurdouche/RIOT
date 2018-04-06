PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=48d641565b412ddc543370f7f0cc2d9a482ae4b7
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp Makefile.hacl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
