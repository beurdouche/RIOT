PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-star.git
PKG_VERSION=43d128c9745413b05deb40386c08d1bbe27dda8f
PKG_LICENSE=Apache-2.0

.PHONY: all

all: git-download
	@"$(MAKE)" -C $(PKG_BUILDDIR)/snapshots/hacl-c riot
	cp $(PKG_BUILDDIR)/snapshots/hacl-c/hacl.a ${BINDIR}/hacl.a

include $(RIOTBASE)/pkg/pkg.mk
