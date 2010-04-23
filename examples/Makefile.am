include $(top_srcdir)/Make_global.am

check_PROGRAMS = rtnl-link-dump rtnl-link-dump2 rtnl-link-dump3 \
		 rtnl-link-event \
		 rtnl-link-set \
		 rtnl-route-add \
		 rtnl-route-dump \
		 genl-family-get

rtnl_link_dump_SOURCES = rtnl-link-dump.c
rtnl_link_dump_LDADD = ../src/libmnl.la
rtnl_link_dump_LDFLAGS = -dynamic -ldl

rtnl_link_dump2_SOURCES = rtnl-link-dump2.c
rtnl_link_dump2_LDADD = ../src/libmnl.la
rtnl_link_dump2_LDFLAGS = -dynamic -ldl

rtnl_link_dump3_SOURCES = rtnl-link-dump3.c
rtnl_link_dump3_LDADD = ../src/libmnl.la
rtnl_link_dump3_LDFLAGS = -dynamic -ldl

rtnl_route_add_SOURCES = rtnl-route-add.c
rtnl_route_add_LDADD = ../src/libmnl.la
rtnl_route_add_LDFLAGS = -dynamic -ldl

rtnl_link_event_SOURCES = rtnl-link-event.c
rtnl_link_event_LDADD = ../src/libmnl.la
rtnl_link_event_LDFLAGS = -dynamic -ldl

rtnl_link_set_SOURCES = rtnl-link-set.c
rtnl_link_set_LDADD = ../src/libmnl.la
rtnl_link_set_LDFLAGS = -dynamic -ldl

rtnl_route_dump_SOURCES = rtnl-route-dump.c
rtnl_route_dump_LDADD = ../src/libmnl.la
rtnl_route_dump_LDFLAGS = -dynamic -ldl

genl_family_get_SOURCES = genl-family-get.c
genl_family_get_LDADD = ../src/libmnl.la
genl_family_get_LDFLAGS = -dynamic -ldl
