include $(top_srcdir)/Make_global.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src include examples
DIST_SUBDIRS = src include examples

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmnl.pc

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
