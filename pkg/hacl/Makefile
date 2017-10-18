PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=6b20596bb853f505f4c86b12698180bd4b0d4ff2
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp $(RIOTBASE)/pkg/hacl/src/* $(PKG_BUILDDIR)
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
