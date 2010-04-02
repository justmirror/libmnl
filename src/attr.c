/*
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libmnl/libmnl.h>
#include <string.h>

/*
 * Netlink Type-Length-Value (TLV) attribute:
 *
 *  |<-- 2 bytes -->|<-- 2 bytes -->|<-- variable -->|
 *  -------------------------------------------------
 *  |     length    |      type     |      value     |
 *  -------------------------------------------------
 *  |<--------- header ------------>|<-- payload --->|
 */

/**
 * mnl_attr_get_type - get the attribute type of a netlink message
 * @attr: pointer to netlink attribute
 *
 * This function returns the attribute type.
 */
uint16_t mnl_attr_get_type(const struct nlattr *attr)
{
	return attr->nla_type & NLA_TYPE_MASK;
}

/**
 * mnl_attr_get_len - get the attribute length
 * @attr: pointer to netlink attribute
 *
 * This function returns the attribute length, including the attribute header.
 */
uint16_t mnl_attr_get_len(const struct nlattr *attr)
{
	return attr->nla_len;
}

/**
 * mnl_attr_get_payload_len - get the attribute payload-value length
 * @attr: pointer to netlink attribute
 *
 * This function returns the attribute payload-value length.
 */
uint16_t mnl_attr_get_payload_len(const struct nlattr *attr)
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
 * mnl_attr_ok - check a there is room for an attribute in a buffer
 * @nlh: attribute that we want to check
 * @len: remaining bytes in a buffer that contains the attribute
 *
 * This function is used to check that a buffer that contains an attribute
 * has enough room for the attribute that it stores, ie. this function can
 * be used to verify that an attribute is neither malformed nor truncated.
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
 * mnl_attr_parse_at_offset - returns an array of attributes from offset
 * @nlh: pointer to netlink message
 * @offset: offset to start parse from
 * @tb: array of pointers to the attribute found
 * @max: size of the attribute array
 *
 * This functions zeroes the array of pointers. Thus, you don't need to
 * initialize this array.
 *
 * This function returns an array of pointers to the attributes that has been
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

/**
 * mnl_attr_parse - returns an array with the attributes in the netlink message
 * @nlh: pointer to netlink message header
 * @tb: array of pointers to the attribute found
 * @max: size of the attribute array
 *
 * This functions zeroes the array of pointers. Thus, you don't need to
 * initialize this array.
 *
 * This function returns an array of pointers to the attributes that has been
 * found in a netlink payload. This function return 0 on sucess, and >0 to
 * indicate the number of bytes the remaining bytes.
 */
int mnl_attr_parse(const struct nlmsghdr *nlh, struct nlattr *tb[], int max)
{
	return mnl_attr_parse_at_offset(nlh, 0, tb, max);
}

/**
 * mnl_attr_parse_nested - returns an array with the attributes from nested
 * @nested: pointer to netlink attribute that contains a nest
 * @tb: array of pointers to the attribute found
 * @max: size of the attribute array
 *
 * This functions zeroes the array of pointers. Thus, you don't need to
 * initialize this array.
 *
 * This function returns an array of pointers to the attributes that has been
 * found in a netlink payload. This function return 0 on sucess, and >0 to
 * indicate the number of bytes the remaining bytes.
 */
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

/**
 * mnl_attr_get_u8 - returns 8-bit unsigned integer attribute.
 * @attr: pointer to netlink attribute
 *
 * This function returns the 8-bit value of a netlink attribute.
 */
uint8_t mnl_attr_get_u8(const struct nlattr *attr)
{
	return *((uint8_t *)mnl_attr_get_data(attr));
}

/**
 * mnl_attr_get_u16 - returns 16-bit unsigned integer attribute.
 * @attr: pointer to netlink attribute
 *
 * This function returns the 16-bit value of a netlink attribute.
 */
uint16_t mnl_attr_get_u16(const struct nlattr *attr)
{
	return *((uint16_t *)mnl_attr_get_data(attr));
}

/**
 * mnl_attr_get_u32 - returns 32-bit unsigned integer attribute.
 * @attr: pointer to netlink attribute
 *
 * This function returns the 32-bit value of a netlink attribute.
 */
uint32_t mnl_attr_get_u32(const struct nlattr *attr)
{
	return *((uint32_t *)mnl_attr_get_data(attr));
}

/**
 * mnl_attr_get_u64 - returns 64-bit unsigned integer attribute.
 * @attr: pointer to netlink attribute
 *
 * This function returns the payload of a 64-bit attribute. This function
 * is align-safe since accessing 64-bit Netlink attributes is a common
 * source of alignment issues.
 */
uint64_t mnl_attr_get_u64(const struct nlattr *attr)
{
	uint64_t tmp;
	memcpy(&tmp, mnl_attr_get_data(attr), sizeof(tmp));
	return tmp;
}

/**
 * mnl_attr_get_str - returns pointer to string attribute.
 * @attr: pointer to netlink attribute
 *
 * This function returns the payload of string attribute value.
 */
const char *mnl_attr_get_str(const struct nlattr *attr)
{
	return (const char *)mnl_attr_get_data(attr);
}

/**
 * mnl_attr_put - add an attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @len: netlink attribute payload size
 * @data: pointer to the data that is stored by the new attribute 
 */
void mnl_attr_put(struct nlmsghdr *nlh, int type, size_t len, const void *data)
{
	struct nlattr *attr = mnl_nlmsg_get_tail(nlh);
	int payload_len = mnl_align(sizeof(struct nlattr)) + len;

	attr->nla_type = type;
	attr->nla_len = payload_len;
	memcpy(mnl_attr_get_data(attr), data, len);
	nlh->nlmsg_len += mnl_align(payload_len);
}

/**
 * mnl_attr_put_u8 - add 8-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @len: netlink attribute payload size
 * @data: 8-bit unsigned integer data that is stored by the new attribute
 */
void mnl_attr_put_u8(struct nlmsghdr *nlh, int type, uint8_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint8_t), &data);
}

/**
 * mnl_attr_put_u16 - add 16-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: 16-bit unsigned integer data that is stored by the new attribute
 */
void mnl_attr_put_u16(struct nlmsghdr *nlh, int type, uint16_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint16_t), &data);
}

/**
 * mnl_attr_put_u32 - add 32-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: 32-bit unsigned integer data that is stored by the new attribute
 */
void mnl_attr_put_u32(struct nlmsghdr *nlh, int type, uint32_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint32_t), &data);
}

/**
 * mnl_attr_put_u64 - add 64-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: 64-bit unsigned integer data that is stored by the new attribute
 */
void mnl_attr_put_u64(struct nlmsghdr *nlh, int type, uint64_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint64_t), &data);
}

/**
 * mnl_attr_put_str - add string attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: pointer to string data that is stored by the new attribute
 */
void mnl_attr_put_str(struct nlmsghdr *nlh, int type, const void *data)
{
	mnl_attr_put(nlh, type, strlen(data), data);
}

/**
 * mnl_attr_put_str_null - add string attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: pointer to string data that is stored by the new attribute
 *
 * This function is similar to mnl_attr_put_str but it includes the NULL
 * terminator at the end of the string.
 */
void mnl_attr_put_str_null(struct nlmsghdr *nlh, int type, const void *data)
{
	mnl_attr_put(nlh, type, strlen(data)+1, data);
}
