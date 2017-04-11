PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-star.git
PKG_VERSION=f23cd173da9adb3a26fd282fef6b768d18169bba
PKG_LICENSE=Apache-2.0

.PHONY: all

all: git-download
	@"$(MAKE)" -C $(PKG_BUILDDIR)/snapshots/hacl-c riot
	cp $(PKG_BUILDDIR)/snapshots/hacl-c/hacl.a ${BINDIR}/hacl.a

include $(RIOTBASE)/pkg/pkg.mk
