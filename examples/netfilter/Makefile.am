include $(top_srcdir)/Make_global.am

check_PROGRAMS = nf-queue \
		 nfct-event

nf_queue_SOURCES = nf-queue.c
nf_queue_LDADD = ../../src/libmnl.la
nf_queue_LDFLAGS = -dynamic -ldl

nfct_event_SOURCES = nfct-event.c
nfct_event_LDADD = ../../src/libmnl.la
nfct_event_LDFLAGS = -dynamic -ldl
