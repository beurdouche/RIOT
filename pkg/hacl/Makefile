PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-star.git
PKG_VERSION=fceaab26887f7622646ee9bab79afc9ff00bf83c
PKG_LICENSE=Apache-2.0

.PHONY: all

all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/riot/lib/libhacl.a ${BINDIR}/libhacl.a

include $(RIOTBASE)/pkg/pkg.mk
