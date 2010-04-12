/*
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <libmnl/libmnl.h>

/*
 * Netlink message:
 *
 *  |<----------------- 4 bytes ------------------->|
 *  |<----- 2 bytes ------>|<------- 2 bytes ------>|
 *
 *  |-----------------------------------------------|
 *  |      Message length (including header)        |
 *  |-----------------------------------------------|
 *  |     Message type     |     Message flags      |
 *  |-----------------------------------------------|
 *  |           Message sequence number             |
 *  |-----------------------------------------------|
 *  |                 Netlink PortID                |
 *  |-----------------------------------------------|
 *  |                                               |
 *  .                   Payload                     .
 *  |_______________________________________________|
 *
 * There is usually an extra header after the the Netlink header (at the
 * beginning of the payload). This extra header is specific of the Netlink
 * subsystem. After this extra header, it comes the sequence of attributes
 * that are expressed in Type-Length-Value (TLV) format.
 */

/**
 * mnl_nlmsg_size - calculate the size of Netlink message (without alignment)
 * @len: length of the Netlink payload
 *
 * This function returns the size of a netlink message (header plus payload)
 * without alignment.
 */
size_t mnl_nlmsg_size(int len)
{
	return len + MNL_ALIGN(MNL_NLMSG_HDRLEN);
}

/**
 * mnl_nlmsg_aligned_size - calculate the aligned size of Netlink messages
 * @len: length of the Netlink payload
 *
 * This function returns the size of a netlink message (header plus payload)
 * with alignment.
 */
size_t mnl_nlmsg_aligned_size(int len)
{
	return MNL_ALIGN(mnl_nlmsg_size(len));
}

/**
 * mnl_nlmsg_get_payload_len - get the length of the Netlink payload
 * @nlh: pointer to the header of the Netlink message
 *
 * This function returns the Length of the netlink payload, ie. the length
 * of the full message minus the size of the Netlink header.
 */
size_t mnl_nlmsg_get_payload_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - MNL_NLMSG_HDRLEN;
}

/**
 * mnl_nlmsg_put_header - reserve and prepare room for Netlink header
 * @buf: memory already allocated to store the Netlink header
 *
 * This function sets to zero the room that is required to put the Netlink
 * header in the memory buffer passed as parameter. This function also
 * initializes the nlmsg_len field to the size of the Netlink header. This
 * function returns a pointer to the Netlink header structure.
 */
struct nlmsghdr *mnl_nlmsg_put_header(void *buf)
{
	int len = MNL_ALIGN(sizeof(struct nlmsghdr));
	struct nlmsghdr *nlh = buf;

	memset(buf, 0, len);
	nlh->nlmsg_len = len;
	return nlh;
}

/**
 * mnl_nlmsg_put_extra_header - reserve and prepare room for an extra header
 * @nlh: pointer to Netlink header
 * @size: size of the extra header that we want to put
 *
 * This function sets to zero the room that is required to put the extra
 * header after the initial Netlink header. This function also increases
 * the nlmsg_len field. You have to invoke mnl_nlmsg_put_header() before
 * you call this function. This function returns a pointer to the extra
 * header.
 */
void *mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, int size)
{
	char *ptr = (char *)nlh + nlh->nlmsg_len;
	nlh->nlmsg_len += MNL_ALIGN(size);
	memset(ptr, 0, size);
	return ptr;
}

/**
 * mnl_nlmsg_get_len - get the length field from the netlink message
 * @nlh: pointer to a netlink header
 *
 * This function returns the full length of the Netlink message (including the
 * length of the Netlink header) by return the field nlmsg_len of the message.
 *
 * XXX: This function is likely to be deleted soon since the structure of the
 * Netlink header is public.
 */
uint16_t mnl_nlmsg_get_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len;
}

/**
 * mnl_nlmsg_get_payload - get a pointer to the payload of the netlink message
 * @nlh: pointer to a netlink header
 *
 * This function returns a pointer to the payload of the netlink message.
 */
void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh)
{
	return (void *)nlh + MNL_NLMSG_HDRLEN;
}

/**
 * mnl_nlmsg_get_payload_offset - get a pointer to the payload of the message
 * @nlh: pointer to a netlink header
 * @offset: offset to the payload of the attributes TLV set
 *
 * This function returns a pointer to the payload of the netlink message plus
 * a given offset.
 */
void *mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh, int offset)
{
	return (void *)nlh + MNL_NLMSG_HDRLEN + MNL_ALIGN(offset);
}

/**
 * mnl_nlmsg_ok - check a there is room for netlink message
 * @nlh: netlink message that we want to check
 * @len: remaining bytes in a buffer that contains the netlink message
 *
 * This function is used to check that a buffer that contains a netlink
 * message has enough room for the netlink message that it stores, ie. this
 * function can be used to verify that a netlink message is not malformed nor
 * truncated.
 *
 * This function does not set errno in case of error since it is intended
 * for iterations. Thus, it returns 1 on success and 0 on error.
 *
 * The @len parameter may become negative in malformed messages during message
 * iteration, that is why we use a signed integer.
 */
int mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len)
{
	return len >= (int)sizeof(struct nlmsghdr) &&
	       nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
	       (int)nlh->nlmsg_len <= len;
}

/**
 * mnl_nlmsg_next - get the next netlink message in a multipart message
 * @nlh: current netlink message that we are handling
 * @len: length of the remaining bytes in the buffer (passed by reference).
 *
 * This function returns a pointer to the next netlink message that is part
 * of a multi-part netlink message. Netlink can batch several messages into
 * one buffer so that the receiver has to iterate over the whole set of
 * Netlink messages.
 *
 * You have to use mnl_nlmsg_ok() to check if the next Netlink message is
 * valid.
 */
struct nlmsghdr *mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len)
{
	*len -= MNL_ALIGN(nlh->nlmsg_len);
	return (struct nlmsghdr *)((void *)nlh + MNL_ALIGN(nlh->nlmsg_len));
}

/**
 * mnl_nlmsg_get_payload_tail - get the ending of the netlink message
 * @nlh: pointer to netlink message
 *
 * This function returns a pointer to the netlink message tail. This is useful
 * to build a message since we continue adding attributes at the end of the
 * message.
 */
void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh)
{
	return (struct nlmsghdr *)((void *)nlh + MNL_ALIGN(nlh->nlmsg_len));
}

/**
 * mnl_nlmsg_seq_ok - perform sequence tracking
 * @nlh: current netlink message that we are handling
 * @seq: last sequence number used to send a message
 *
 * This functions returns 1 if the sequence tracking is fulfilled, otherwise
 * 0 is returned. We skip the tracking for netlink messages whose sequence
 * number is zero since it is usually reserved for event-based kernel
 * notifications.
 */
int mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq)
{
	return nlh->nlmsg_seq ? nlh->nlmsg_seq == seq : 1;
}

/**
 * mnl_nlmsg_portid_ok - perform portID origin check
 * @nlh: current netlink message that we are handling
 * @seq: netlink portid that we want to check
 *
 * This functions return 1 if the origin is fulfilled, otherwise
 * 0 is returned.  We skip the tracking for netlink message whose portID 
 * is zero since it is reserved for event-based kernel notifications.
 */
int mnl_nlmsg_portid_ok(const struct nlmsghdr *nlh, unsigned int portid)
{
	return nlh->nlmsg_pid ? nlh->nlmsg_pid == portid : 1;
}

/* XXX: rework this, please */
void mnl_nlmsg_print(const struct nlmsghdr *nlh)
{
	int i;

	printf("========= netlink header ==========\n");
	printf("length(32 bits)=%.08u\n", nlh->nlmsg_len);
	printf("type(16 bits)=%.04u flags(16 bits)=%.04x\n",
		nlh->nlmsg_type, nlh->nlmsg_flags);
	printf("sequence number(32 bits)=%.08x\n", nlh->nlmsg_seq);
	printf("port ID(32 bits)=%.08u\n", nlh->nlmsg_pid);
	printf("===================================\n");

	for (i=sizeof(struct nlmsghdr); i<mnl_nlmsg_get_len(nlh); i+=4) {
		char *b = (char *) nlh;

		printf("(%.3d) %.2x %.2x %.2x %.2x | ", i,
			0xff & b[i],	0xff & b[i+1],
			0xff & b[i+2],	0xff & b[i+3]);

		printf("%c %c %c %c\n",
			isalnum(b[i]) ? b[i] : 0,
			isalnum(b[i+1]) ? b[i+1] : 0,
			isalnum(b[i+2]) ? b[i+2] : 0,
			isalnum(b[i+3]) ? b[i+3] : 0);
	}
}
