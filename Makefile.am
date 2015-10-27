# Copyright 2013 - 2015 Who Is On My WiFi.
#
# This file is part of Who Is On My WiFi Linux.
#
# Who Is On My WiFi Linux is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# Who Is On My WiFi Linux is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
#
# More information about Who Is On My WiFi Linux can be found at
# <http://www.whoisonmywifi.com/>.
#

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src etc

PKGVER=$(PACKAGE)-$(VERSION)
PKG_VER=$(PACKAGE)_$(VERSION)

CLEANFILES = $(PACKAGE)_*.*.*-1_*.build

clean-local: clean-local-deb
.PHONY: clean-local-deb
clean-local-deb:
	-rm -rf $(PKGVER)

DISTCLEANFILES = $(PACKAGE)-*.*.*.tar.gz \
		 $(PACKAGE)_*.*.*.orig.tar.gz \
		 $(PACKAGE)_*.*.*-1.dsc \
		 $(PACKAGE)_*.*.*-1.debian.tar.gz \
		 $(PACKAGE)_*.*.*-1_*.changes \
		 $(PACKAGE)_*.*.*-1_*.deb

if BUILD_DEB
deb: dist
	@echo "Building debian package..."; \
	if test ! -d debian; then \
		echo "To build a debian package," \
		" you must get a fresh copy of the source package," \
		" not a copy of the dist tarball."; \
		exit 1; \
	fi; \
	cp -v $(PKGVER).tar.gz $(PKG_VER).orig.tar.gz && \
	$(TAR) xvzf $(PKG_VER).orig.tar.gz && \
	cd $(PKGVER) && \
	cp -rv ../debian ./. && \
	DEBEMAIL="support@whoisonmywifi.com" DEBFULLNAME="Who's On My WiFi" \
	$(DCH) $(DCH_ARGS) -v $(VERSION)-1 --package $(PACKAGE) \
	"Debian package generated from source" && \
	$(DPKG_BUILD) $(DPKG_BUILD_ARGS); \
	cd $(srcdir); \
	rm -vf $(PKG_VER).orig.tar.gz; \
	rm -rvf $(PKGVER)
else
deb:
	@echo "To build a debian package," \
		" you must run configure with the --enable-deb flag."; \
	exit 1
endif

