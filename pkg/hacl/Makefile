PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=b07286037d3edac73c7c410c3fbd92d9b6f7998d
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp $(RIOTBASE)/pkg/hacl/src/* $(PKG_BUILDDIR)
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
