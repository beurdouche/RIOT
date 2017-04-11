PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-star.git
PKG_VERSION=b9f6fe58a327c7517f7f8c6b0c0635bb192b33a5
PKG_LICENSE=Apache-2.0

.PHONY: all

all: git-download
	@$(MAKE) -C $(PKG_BUILDDIR)/snapshots/hacl-c riot

include $(RIOTBASE)/pkg/pkg.mk
