PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=480cbce725a2ccd4359d1907cf3ae45165451db5
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	@cp Makefile.hacl $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR) 

include $(RIOTBASE)/pkg/pkg.mk
