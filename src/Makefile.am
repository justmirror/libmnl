include $(top_srcdir)/Make_global.am

AM_CFLAGS=-fPIC -Wall -Wextra -Wno-unused-parameter
LIBS=

lib_LTLIBRARIES = libmnl.la

libmnl_la_LDFLAGS = -Wc,-nostartfiles -version-info $(LIBVERSION)
libmnl_la_SOURCES = socket.c callback.c nlmsg.c attr.c
