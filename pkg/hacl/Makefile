PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=1e16e9405de76fd056001f03748a1b647dbb258f
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp $(RIOTBASE)/pkg/hacl/src/* $(PKG_BUILDDIR)
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
