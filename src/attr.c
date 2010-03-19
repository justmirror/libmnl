/*
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include <libmnl/libmnl.h>
#include <string.h>

/**
 * Netlink attribute:
 *
 *  |<-- 2 bytes -->|<-- 2 bytes -->|<-- variable -->|
 *  -------------------------------------------------
 *  |     length    |      type     |      value     |
 *  -------------------------------------------------
 */

/**
 * mnl_attr_get_type - get the attribute type of a netlink message
 *
 * This function returns the attribute type.
 */
u_int16_t mnl_attr_get_type(const struct nlattr *attr)
{
	return attr->nla_type & NLA_TYPE_MASK;
}

/**
 * mnl_attr_get_len - get the attribute length
 *
 * This function returns the attribute length.
 */
u_int16_t mnl_attr_get_len(const struct nlattr *attr)
{
	return attr->nla_len;
}

/**
 * mnl_attr_get_payload_len - get the attribute payload length
 *
 * This function returns the attribute payload length.
 */
u_int16_t mnl_attr_get_payload_len(const struct nlattr *attr)
{
	return attr->nla_len - MNL_ATTR_HDRLEN;
}

/**
 * mnl_attr_get_data - get pointer to the attribute payload
 *
 * This function return a pointer to the attribute payload
 */
void *mnl_attr_get_data(const struct nlattr *attr)
{
	return (void *)attr + MNL_ATTR_HDRLEN;
}

/**
 * mnl_attr_ok - check a there is room for an attribute
 * @nlh: attribute that we want to check
 * @len: remaining bytes in a buffer that contains the attribute
 *
 * This function is used to check that a buffer that contains an attribute
 * has enough room for the attribute that it stores, ie. this function can
 * be used to verify that an attribute is not malformed nor truncated.
 */
int mnl_attr_ok(const struct nlattr *attr, int len)
{
	return len >= sizeof(struct nlattr) &&
	       attr->nla_len >= sizeof(struct nlattr) &&
	       attr->nla_len <= len;
}

/**
 * mnl_attr_next - get the next attribute in the payload of a netlink message
 * @attr: pointer to the current attribute
 * @len: pointer to the current remaining bytes in the buffer
 *
 * This function returns a pointer to the next attribute that is in the
 * payload of a netlink message.
 */
struct nlattr *mnl_attr_next(const struct nlattr *attr, int *len)
{
	*len -= mnl_align(attr->nla_len);
	return (struct nlattr *)((void *)attr + mnl_align(attr->nla_len));
}

/**
 * mnl_attr_parse - returns an array with the attributes in a message
 * @tb: array of pointers to the attribute found
 * @tb_size: size of the attribute array
 * @attr: first attribute in the stream
 * @len: remaining bytes in the buffer that contain attributes
 *
 * This function returns a table of pointers to the attributes that has been
 * found in a netlink payload. This function return 0 on sucess, and >0 to
 * indicate the number of bytes the remaining bytes.
 */
int mnl_attr_parse_at_offset(const struct nlmsghdr *nlh, int offset,
			      struct nlattr *tb[], int max)
{
	struct nlattr *attr = mnl_nlmsg_get_data_offset(nlh, offset);
	int len = mnl_nlmsg_get_len(nlh);

	memset(tb, 0, sizeof(struct nlattr *) * (max + 1));

	while (mnl_attr_ok(attr, len)) {
		if (mnl_attr_get_type(attr) <= max)
			tb[mnl_attr_get_type(attr)] = attr;
		attr = mnl_attr_next(attr, &len);
	}
	return len;
}

int mnl_attr_parse(const struct nlmsghdr *nlh, struct nlattr *tb[], int max)
{
	return mnl_attr_parse_at_offset(nlh, 0, tb, max);
}

int mnl_attr_parse_nested(const struct nlattr *nested,
			   struct nlattr *tb[], int max)
{
	struct nlattr *attr = mnl_attr_get_data(nested);
	int len = mnl_attr_get_payload_len(nested);

	memset(tb, 0, sizeof(struct nlattr *) * (max + 1));

	while (mnl_attr_ok(attr, len)) {
		if (mnl_attr_get_type(attr) <= max)
			tb[mnl_attr_get_type(attr)] = attr;
		attr = mnl_attr_next(attr, &len);
	}
	return len;
}

u_int8_t mnl_attr_get_u8(const struct nlattr *attr)
{
	return *((u_int8_t *)mnl_attr_get_data(attr));
}

u_int16_t mnl_attr_get_u16(const struct nlattr *attr)
{
	return *((u_int16_t *)mnl_attr_get_data(attr));
}

u_int32_t mnl_attr_get_u32(const struct nlattr *attr)
{
	return *((u_int32_t *)mnl_attr_get_data(attr));
}

/**
 * mnl_attr_get_u64 - returns an arra
 * @attr: netlink attribute
 *
 * This function returns the payload of a 64-bits attribute. This function
 * is align-safe since accessing 64-bits Netlink attributes is a common
 * source of alignment issues.
 */
u_int64_t mnl_attr_get_u64(const struct nlattr *attr)
{
	u_int64_t tmp;
	memcpy(&tmp, mnl_attr_get_data(attr), sizeof(tmp));
	return tmp;
}

const char *mnl_attr_get_str(const struct nlattr *attr)
{
	return (const char *)mnl_attr_get_data(attr);
}

void mnl_attr_put(struct nlmsghdr *nlh, int type, size_t len, const void *data)
{
	struct nlattr *attr = mnl_nlmsg_get_tail(nlh);
	int payload_len = mnl_align(sizeof(struct nlattr)) + len;

	attr->nla_type = type;
	attr->nla_len = payload_len;
	memcpy(mnl_attr_get_data(attr), data, len);
	nlh->nlmsg_len += mnl_align(payload_len);
}

void mnl_attr_put_u8(struct nlmsghdr *nlh, int type, u_int8_t data)
{
	mnl_attr_put(nlh, type, sizeof(u_int8_t), &data);
}

void mnl_attr_put_u16(struct nlmsghdr *nlh, int type, u_int16_t data)
{
	mnl_attr_put(nlh, type, sizeof(u_int16_t), &data);
}

void mnl_attr_put_u32(struct nlmsghdr *nlh, int type, u_int32_t data)
{
	mnl_attr_put(nlh, type, sizeof(u_int32_t), &data);
}

void mnl_attr_put_u64(struct nlmsghdr *nlh, int type, u_int64_t data)
{
	mnl_attr_put(nlh, type, sizeof(u_int64_t), &data);
}

void mnl_attr_put_str(struct nlmsghdr *nlh, int type, const void *data)
{
	mnl_attr_put(nlh, type, strlen(data), data);
}

void mnl_attr_put_str_null(struct nlmsghdr *nlh, int type, const void *data)
{
	mnl_attr_put(nlh, type, strlen(data)+1, data);
}
