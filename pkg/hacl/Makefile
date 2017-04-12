PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-star.git
PKG_VERSION=44623669cda8e9ba6836ed101f63c497a16d6e01
PKG_LICENSE=Apache-2.0

.PHONY: all

all: git-download
	@"$(MAKE)" -C $(PKG_BUILDDIR)/snapshots/hacl-c riot
	cp $(PKG_BUILDDIR)/snapshots/hacl-c/hacl.a ${BINDIR}/hacl.a

include $(RIOTBASE)/pkg/pkg.mk
