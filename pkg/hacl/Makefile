PKG_NAME=hacl
PKG_URL=https://github.com/mitls/hacl-c
PKG_VERSION=89d172a204379da2d063ee3ae6d12363aba13078
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk
