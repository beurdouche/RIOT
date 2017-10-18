PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=523ff72791a9e3628a1050eb4ba9427630abd5f6
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp $(RIOTBASE)/pkg/hacl/src/* $(PKG_BUILDDIR)
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
