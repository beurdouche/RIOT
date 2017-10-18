PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=2f17c6816dca814e31dbf781f0e81a66783953a5
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp $(RIOTBASE)/pkg/hacl/src/* $(PKG_BUILDDIR)
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
