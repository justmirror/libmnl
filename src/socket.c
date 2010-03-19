/*
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include <libmnl/libmnl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

struct mnl_socket {
	int 			fd;
	struct sockaddr_nl	addr;
};

/**
 * mnl_socket_get_fd - obtain file descriptor from netlink socket
 * @nl: netlink socket obtained via mnl_socket_open()
 *
 * This function returns the file descriptor of a given netlink socket.
 */
int mnl_socket_get_fd(const struct mnl_socket *nl)
{
	return nl->fd;
}

/**
 * mnl_socket_get_portid - obtain Netlink PortID from netlink socket
 * @nl: netlink socket obtained via mnl_socket_open()
 *
 * This function returns the Netlink PortID of a given netlink socket.
 * It's a common mistake to assume that this PortID equals the process ID
 * which is not always true. This is the case if you open more than one
 * socket that is binded to the same Netlink subsystem.
 */
unsigned int mnl_socket_get_portid(const struct mnl_socket *nl)
{
	return nl->addr.nl_pid;
}

/**
 * mnl_socket_open - open a netlink socket
 * @unit: the netlink socket unit (see NETLINK_* constants)
 *
 * On error, it returns -1 and errno is appropriately set. Otherwise, it
 * returns a valid pointer to the mnl_socket structure.
 */
struct mnl_socket *mnl_socket_open(int unit)
{
	struct mnl_socket *nl;

	nl = calloc(sizeof(struct mnl_socket), 1);
	if (nl == NULL)
		return NULL;

	nl->fd = socket(AF_NETLINK, SOCK_RAW, unit);
	if (nl->fd == -1) {
		free(nl);
		return NULL;
	}

	return nl;
}

/**
 * mnl_socket_bind - bind netlink socket
 * @nl: netlink socket obtained via mnl_socket_open()
 * @groups: the group of message you're interested in
 * @pid: the port ID you want to use (use zero for automatic selection)
 *
 * On error, this function returns -1 and errno is appropriately set. On
 * success, 0 is returned.
 */
int mnl_socket_bind(struct mnl_socket *nl, int groups, int pid)
{
	int ret;
	socklen_t addr_len;

	nl->addr.nl_family = AF_NETLINK;
	nl->addr.nl_groups = groups;

	ret = bind(nl->fd, (struct sockaddr *) &nl->addr, sizeof (nl->addr));
	if (ret < 0)
		return ret;

	addr_len = sizeof(nl->addr);
	ret = getsockname(nl->fd, (struct sockaddr *) &nl->addr, &addr_len);
	if (ret < 0)	
		return ret;

	if (addr_len != sizeof(nl->addr)) {
		errno = EINVAL;
		return -1;
	}
	if (nl->addr.nl_family != AF_NETLINK) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/**
 * mnl_socket_sendto - send a netlink message of a certain size
 * @nl: netlink socket obtained via mnl_socket_open()
 * @buf: buffer containing the netlink message to be sent
 * @bufsiz: number of bytes in the buffer that you want to send
 *
 * On error, it returns -1 and errno is appropriately set. Otherwise, it 
 * returns the number of bytes sent.
 */
int mnl_socket_sendto(struct mnl_socket *nl, const void *buf, int len)
{
	struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	return sendto(nl->fd, buf, len, 0, 
		      (struct sockaddr *) &snl, sizeof(snl));
}

/**
 * mnl_socket_sendmsg - send a netlink message of a certain size
 * @nl: netlink socket obtained via mnl_socket_open()
 * @msg: pointer to struct msghdr (must be initialized appropriately)
 * @flags: flags passed to sendmsg()
 *
 * On error, it returns -1 and errno is appropriately set. Otherwise, it 
 * returns the number of bytes sent.
 */
int
mnl_socket_sendmsg(struct mnl_socket *nl, struct msghdr *msg, int flags)
{
	return sendmsg(nl->fd, msg, flags);
}

/**
 * mnl_socket_recvfrom - receive a netlink message
 * @nl: netlink socket obtained via mnl_socket_open()
 * @buf: buffer that you want to use to store the netlink message
 * @bufsiz: size of the buffer passed to store the netlink message
 *
 * On error, it returns -1 and errno is appropriately set. If errno is set
 * to ENOSPC, it means that the buffer that you have passed to store the
 * netlink message is small so you have received a truncated message. Make
 * sure your program set a buffer big enough to store the netlink message.
 */
int mnl_socket_recvfrom(struct mnl_socket *nl, void *buf, int bufsiz)
{
	int ret;
	struct sockaddr_nl addr;
	struct iovec iov = {
		.iov_base	= buf,
		.iov_len	= bufsiz,
	};
	struct msghdr msg = {
		.msg_name	= (void *)&addr,
		.msg_namelen	= sizeof(struct sockaddr_nl),
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= NULL,
		.msg_controllen	= 0,
		.msg_flags	= 0,
	};
	ret = recvmsg(nl->fd, &msg, 0);
	if (ret == -1)
		return ret;

	if (msg.msg_flags & MSG_TRUNC) {
		errno = ENOSPC;
		return -1;
	}
	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		errno = EINVAL;
		return -1;
	}
	return ret;
}

/**
 * mnl_socket_recvmsg- receive a netlink message
 * @nl: netlink socket obtained via mnl_socket_open()
 * @msg: pointer to struct msghdr (must be initialized appropriately)
 * @flags: flags passed to recvmsg()
 *
 * On error, this function returns -1 and errno is appropriately set.
 * On sucess, this function returns the number of bytes received.
 */
int
mnl_socket_recvmsg(const struct mnl_socket *nl, struct msghdr *msg, int flags)
{
	return recvmsg(nl->fd, msg, flags);
}

/**
 * mnl_socket_close - close a given netlink socket
 * @nl: netlink socket obtained via mnl_socket_open()
 *
 * On error, this function returns -1 and errno is appropriately set.
 * On success, it returns 0.
 */
int mnl_socket_close(struct mnl_socket *nl)
{
	int ret = close(nl->fd);
	free(nl);
	nl = NULL;
	return ret;
}

/**
 * mnl_socket_setsockopt - set Netlink socket option
 * @nl: netlink socket obtained via mnl_socket_open()
 * @type: type of Netlink socket options
 * @buf: the buffer that contains the data about this option
 * @len: the size of the buffer passed
 *
 * This function allows you to set some Netlink socket option. As of writing
 * this, the existing options are:
 *
 * #define NETLINK_ADD_MEMBERSHIP  1
 * #define NETLINK_DROP_MEMBERSHIP 2
 * #define NETLINK_PKTINFO         3
 * #define NETLINK_BROADCAST_ERROR 4
 * #define NETLINK_NO_ENOBUFS      5
 *
 * In the early days, Netlink only supported 32 groups expressed in a
 * 32-bits mask. However, since 2.6.14, Netlink may have up to 2^32 multicast
 * groups but you have to use setsockopt() with NETLINK_ADD_MEMBERSHIP to
 * join a given multicast group. This function internally calls setsockopt()
 * to join a given netlink multicast group. You can still use mnl_bind()
 * and the 32-bit mask to join a set of Netlink multicast groups.
 *
 * On error, this function returns -1 and errno is appropriately set.
 */
int mnl_socket_setsockopt(struct mnl_socket *nl, int type,
			  void *buf, socklen_t len)
{
	return setsockopt(nl->fd, SOL_NETLINK, type, buf, len);
}

/**
 * mnl_socket_getsockopt - get a Netlink socket option
 * @nl: netlink socket obtained via mnl_socket_open()
 * @type: type of Netlink socket options
 * @buf: pointer to the buffer to store the value of this option
 * @len: size of the information written in the buffer
 *
 * On error, this function returns -1 and errno is appropriately set.
 */
int mnl_socket_getsockopt(struct mnl_socket *nl, int type,
			  void *buf, socklen_t *len)
{
	return getsockopt(nl->fd, SOL_NETLINK, type, buf, len);
}
