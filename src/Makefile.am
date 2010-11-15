include $(top_srcdir)/Make_global.am
AM_CFLAGS += $(CFLAG_VISIBILITY)
AM_CPPFLAGS += -DBUILDING_MNL
lib_LTLIBRARIES = libmnl.la

libmnl_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libmnl.map -version-info $(LIBVERSION)
libmnl_la_SOURCES = socket.c callback.c nlmsg.c attr.c
