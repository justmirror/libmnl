#ifndef _LIBMNL_H_
#define _LIBMNL_H_

#include <sys/socket.h> /* for sa_family_t */
#include <linux/netlink.h>

/*
 * generic netlink socket API
 */

#define MNL_SOCKET_AUTOPID	0

struct mnl_socket;

extern struct mnl_socket *mnl_socket_open(int type);
extern int mnl_socket_bind(struct mnl_socket *nl, int groups, int pid);
extern int mnl_socket_close(struct mnl_socket *nl);
extern int mnl_socket_get_fd(const struct mnl_socket *nl);
extern unsigned int mnl_socket_get_portid(const struct mnl_socket *nl);
extern int mnl_socket_sendto(struct mnl_socket *nl, const void *req, int siz);
extern int mnl_socket_sendmsg(struct mnl_socket *nl, struct msghdr *msg, int flags);
extern int mnl_socket_recvfrom(struct mnl_socket *nl, void *buf, int siz);
extern int mnl_socket_recvmsg(const struct mnl_socket *nl, struct msghdr *msg, int flags);
extern int mnl_socket_setsockopt(struct mnl_socket *nl, int type, void *buf, socklen_t len);
extern int mnl_socket_getsockopt(struct mnl_socket *nl, int type, void *buf, socklen_t *len);

/*
 * generic netlink message API
 */

#define MNL_ALIGNTO	4
#define MNL_NLMSG_HDRLEN	mnl_align(sizeof(struct nlmsghdr))

extern int mnl_align(int len);
extern size_t mnl_nlmsg_size(int len);
extern size_t mnl_nlmsg_total_size(int len);
extern size_t mnl_nlmsg_payload_size(const struct nlmsghdr *nlh);

/* Netlink message header builder */
extern struct nlmsghdr *mnl_nlmsg_put_header(void *buf);
extern void *mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, int size);

/* Netlink message iterators */
extern int mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len);
extern struct nlmsghdr *mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len);

/* Netlink sequence tracking */
extern int mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq);

/* Netlink header getters */
extern u_int16_t mnl_nlmsg_get_len(const struct nlmsghdr *nlh);
extern void *mnl_nlmsg_get_data(const struct nlmsghdr *nlh);
extern void *mnl_nlmsg_get_data_offset(const struct nlmsghdr *nlh, int offset);
extern void *mnl_nlmsg_get_tail(const struct nlmsghdr *nlh);

/* Netlink dump message */
extern void mnl_nlmsg_print(const struct nlmsghdr *nlh);

/*
 * generic netlink attributes API
 */
#define MNL_ATTR_HDRLEN	mnl_align(sizeof(struct nlattr))

/* TLV attribute getters */
extern u_int16_t mnl_attr_get_type(const struct nlattr *attr);
extern u_int16_t mnl_attr_get_len(const struct nlattr *attr);
extern u_int16_t mnl_attr_get_payload_len(const struct nlattr *attr);
extern void *mnl_attr_get_data(const struct nlattr *attr);
extern u_int8_t mnl_attr_get_u8(const struct nlattr *attr);
extern u_int16_t mnl_attr_get_u16(const struct nlattr *attr);
extern u_int32_t mnl_attr_get_u32(const struct nlattr *attr);
extern u_int64_t mnl_attr_get_u64(const struct nlattr *attr);
extern const char *mnl_attr_get_str(const struct nlattr *attr);

/* TLV attribute putters */
extern void mnl_attr_put(struct nlmsghdr *nlh, int type, size_t len, const void *data);
extern void mnl_attr_put_u8(struct nlmsghdr *nlh, int type, u_int8_t data);
extern void mnl_attr_put_u16(struct nlmsghdr *nlh, int type, u_int16_t data);
extern void mnl_attr_put_u32(struct nlmsghdr *nlh, int type, u_int32_t data);
extern void mnl_attr_put_u64(struct nlmsghdr *nlh, int type, u_int64_t data);
extern void mnl_attr_put_str(struct nlmsghdr *nlh, int type, const void *data);
extern void mnl_attr_put_str_null(struct nlmsghdr *nlh, int type, const void *data);

/* TLV attribute parsers */
extern int mnl_attr_parse(const struct nlmsghdr *nlh, struct nlattr *tb[], int max);
extern int mnl_attr_parse_at_offset(const struct nlmsghdr *nlh, int offset, struct nlattr *tb[], int max);
extern int mnl_attr_parse_nested(const struct nlattr *attr, struct nlattr *tb[], int max);
extern int mnl_attr_ok(const struct nlattr *attr, int len);
extern struct nlattr *mnl_attr_next(const struct nlattr *attr, int *len);

#define mnl_attr_for_each_nested(pos, head, len)			    \
	for (pos = mnl_attr_get_data(head), len = mnl_attr_get_len(head); \
	     mnl_attr_ok(pos, len);					    \
	     pos = mnl_attr_next(pos, &(len)))

/*
 * callback API
 */
#define MNL_CB_ERROR		-1
#define MNL_CB_STOP		 0
#define MNL_CB_OK		 1

typedef int (*mnl_cb_t)(const struct nlmsghdr *nlh, void *data);

extern int mnl_cb_run(const char *buf, int numbytes, unsigned int seq,
		      mnl_cb_t cb_data, void *data);

extern int mnl_cb_run2(const char *buf, int numbytes,
		       unsigned int seq, mnl_cb_t cb_data, void *data,
		       mnl_cb_t *cb_ctl_array, unsigned int cb_ctl_array_len);

/*
 * other declarations
 */

#ifndef SOL_NETLINK
#define SOL_NETLINK	270
#endif

#endif
