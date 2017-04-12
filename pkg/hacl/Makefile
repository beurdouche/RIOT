PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-star.git
PKG_VERSION=4fcf52cbc3fcc9cf7b269223c9d0ae91141b0f2c
PKG_LICENSE=Apache-2.0

.PHONY: all

all: git-download
	@"$(MAKE)" -C $(PKG_BUILDDIR)/snapshots/hacl-c riot
	cp $(PKG_BUILDDIR)/snapshots/hacl-c/hacl.a ${BINDIR}/hacl.a

include $(RIOTBASE)/pkg/pkg.mk
