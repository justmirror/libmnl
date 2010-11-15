#ifndef _LIBMNL_H_
#define _LIBMNL_H_

#ifdef __cplusplus
#	include <cstdio>
#	include <cstdint>
#else
#	include <stdbool.h> /* not in C++ */
#	include <stdio.h>
#	include <stdint.h>
#endif
#include <sys/socket.h> /* for sa_family_t */
#include <linux/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HAVE_VISIBILITY) && defined(BUILDING_MNL)
#define MNL_API extern  __attribute__ ((visibility("default")))
#else
#define MNL_API extern
#endif

/*
 * Netlink socket API
 */

#define MNL_SOCKET_AUTOPID	0
#define MNL_SOCKET_BUFFER_SIZE	8192UL	/* see linux/netlink.h */

struct mnl_socket;

MNL_API struct mnl_socket *mnl_socket_open(int type);
MNL_API int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid);
MNL_API int mnl_socket_close(struct mnl_socket *nl);
MNL_API int mnl_socket_get_fd(const struct mnl_socket *nl);
MNL_API unsigned int mnl_socket_get_portid(const struct mnl_socket *nl);
MNL_API int mnl_socket_sendto(const struct mnl_socket *nl, const void *req, size_t siz);
MNL_API int mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t siz);
MNL_API int mnl_socket_setsockopt(const struct mnl_socket *nl, int type, void *buf, socklen_t len);
MNL_API int mnl_socket_getsockopt(const struct mnl_socket *nl, int type, void *buf, socklen_t *len);

/*
 * Netlink message API
 */

#define MNL_ALIGNTO		4
#define MNL_ALIGN(len)		(((len)+MNL_ALIGNTO-1) & ~(MNL_ALIGNTO-1))
#define MNL_NLMSG_HDRLEN	MNL_ALIGN(sizeof(struct nlmsghdr))

MNL_API size_t mnl_nlmsg_size(size_t len);
MNL_API size_t mnl_nlmsg_total_size(size_t len);
MNL_API size_t mnl_nlmsg_get_payload_len(const struct nlmsghdr *nlh);

/* Netlink message header builder */
MNL_API struct nlmsghdr *mnl_nlmsg_put_header(void *buf);
MNL_API void *mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, size_t size);

/* Netlink message iterators */
MNL_API bool mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len);
MNL_API struct nlmsghdr *mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len);

/* Netlink sequence tracking */
MNL_API bool mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq);

/* Netlink portID checking */
MNL_API bool mnl_nlmsg_portid_ok(const struct nlmsghdr *nlh, unsigned int portid);

/* Netlink message getters */
MNL_API void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh);
MNL_API void *mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh, size_t offset);
MNL_API void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh);

/* Netlink message printer */
MNL_API void mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen, size_t extra_header_size);

/*
 * Netlink attributes API
 */
#define MNL_ATTR_HDRLEN	MNL_ALIGN(sizeof(struct nlattr))

/* TLV attribute getters */
MNL_API uint16_t mnl_attr_get_type(const struct nlattr *attr);
MNL_API uint16_t mnl_attr_get_len(const struct nlattr *attr);
MNL_API uint16_t mnl_attr_get_payload_len(const struct nlattr *attr);
MNL_API void *mnl_attr_get_payload(const struct nlattr *attr);
MNL_API uint8_t mnl_attr_get_u8(const struct nlattr *attr);
MNL_API uint16_t mnl_attr_get_u16(const struct nlattr *attr);
MNL_API uint32_t mnl_attr_get_u32(const struct nlattr *attr);
MNL_API uint64_t mnl_attr_get_u64(const struct nlattr *attr);
MNL_API const char *mnl_attr_get_str(const struct nlattr *attr);

/* TLV attribute putters */
MNL_API void mnl_attr_put(struct nlmsghdr *nlh, uint16_t type, size_t len, const void *data);
MNL_API void mnl_attr_put_u8(struct nlmsghdr *nlh, uint16_t type, uint8_t data);
MNL_API void mnl_attr_put_u16(struct nlmsghdr *nlh, uint16_t type, uint16_t data);
MNL_API void mnl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t data);
MNL_API void mnl_attr_put_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t data);
MNL_API void mnl_attr_put_str(struct nlmsghdr *nlh, uint16_t type, const char *data);
MNL_API void mnl_attr_put_strz(struct nlmsghdr *nlh, uint16_t type, const char *data);

/* TLV attribute nesting */
MNL_API struct nlattr *mnl_attr_nest_start(struct nlmsghdr *nlh, uint16_t type);
MNL_API void mnl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start);

/* TLV validation */
MNL_API int mnl_attr_type_valid(const struct nlattr *attr, uint16_t maxtype);

enum mnl_attr_data_type {
	MNL_TYPE_UNSPEC,
	MNL_TYPE_U8,
	MNL_TYPE_U16,
	MNL_TYPE_U32,
	MNL_TYPE_U64,
	MNL_TYPE_STRING,
	MNL_TYPE_FLAG,
	MNL_TYPE_MSECS,
	MNL_TYPE_NESTED,
	MNL_TYPE_NESTED_COMPAT,
	MNL_TYPE_NUL_STRING,
	MNL_TYPE_BINARY,
	MNL_TYPE_MAX,
};

MNL_API int mnl_attr_validate(const struct nlattr *attr, enum mnl_attr_data_type type);
MNL_API int mnl_attr_validate2(const struct nlattr *attr, enum mnl_attr_data_type type, size_t len);

/* TLV iterators */
MNL_API bool mnl_attr_ok(const struct nlattr *attr, int len);
MNL_API struct nlattr *mnl_attr_next(const struct nlattr *attr, int *len);

#define mnl_attr_for_each(attr, nlh, offset)			\
	int __len__ = mnl_nlmsg_get_payload_len(nlh);		\
	for (attr = mnl_nlmsg_get_payload_offset(nlh, offset);	\
	     mnl_attr_ok(attr, __len__);			\
	     attr = mnl_attr_next(attr, &(__len__)))

#define mnl_attr_for_each_nested(attr, nest)			\
	int __len__ = mnl_attr_get_len(nest);			\
	for (attr = mnl_attr_get_payload(nest);			\
	     mnl_attr_ok(attr, __len__);			\
	     attr = mnl_attr_next(attr, &(__len__)))

/* TLV callback-based attribute parsers */
typedef int (*mnl_attr_cb_t)(const struct nlattr *attr, void *data);

MNL_API int mnl_attr_parse(const struct nlmsghdr *nlh, unsigned int offset, mnl_attr_cb_t cb, void *data);
MNL_API int mnl_attr_parse_nested(const struct nlattr *attr, mnl_attr_cb_t cb, void *data);

/*
 * callback API
 */
#define MNL_CB_ERROR		-1
#define MNL_CB_STOP		 0
#define MNL_CB_OK		 1

typedef int (*mnl_cb_t)(const struct nlmsghdr *nlh, void *data);

MNL_API int mnl_cb_run(const void *buf, size_t numbytes, unsigned int seq,
		      unsigned int portid, mnl_cb_t cb_data, void *data);

MNL_API int mnl_cb_run2(const void *buf, size_t numbytes, unsigned int seq,
		       unsigned int portid, mnl_cb_t cb_data, void *data,
		       mnl_cb_t *cb_ctl_array, unsigned int cb_ctl_array_len);

/*
 * other declarations
 */

#ifndef SOL_NETLINK
#define SOL_NETLINK	270
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
