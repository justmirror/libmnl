#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[getpagesize()];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	int ret;
	unsigned int seq, portid, oper;

	if (argc != 3) {
		printf("Usage: %s [ifname] [up|down]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strncasecmp(argv[2], "up") == 0)
		oper = IF_OPER_UP;
	else if (strncasecmp(argv[2], "down") == 0)
		oper = IF_OPER_DOWN;
	else {
		fprintf(stderr, "%s is not `up' nor `down'\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);
	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_PACKET;

	mnl_attr_put_u8(nlh, IFLA_OPERSTATE, oper);
	mnl_attr_put_str(nlh, IFLA_IFNAME, argv[1]);

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	mnl_nlmsg_fprintf(stdout, nlh);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (ret == -1){
		perror("callback");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}
