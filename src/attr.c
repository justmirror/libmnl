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
#include <values.h>	/* for INT_MAX */
#include <errno.h>

/*
 * Netlink Type-Length-Value (TLV) attribute:
 *
 *  |<-- 2 bytes -->|<-- 2 bytes -->|<-- variable -->|
 *  -------------------------------------------------
 *  |     length    |      type     |      value     |
 *  -------------------------------------------------
 *  |<--------- header ------------>|<-- payload --->|
 *
 * The payload of the Netlink message contains sequences of attributes that are
 * expressed in TLV format.
 */

/**
 * mnl_attr_get_type - get type of netlink attribute
 * @attr: pointer to netlink attribute
 *
 * This function returns the attribute type.
 */
uint16_t mnl_attr_get_type(const struct nlattr *attr)
{
	return attr->nla_type & NLA_TYPE_MASK;
}

/**
 * mnl_attr_get_len - get length of netlink attribute
 * @attr: pointer to netlink attribute
 *
 * This function returns the attribute length that is the attribute header
 * plus the attribute payload.
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
 * mnl_attr_get_payload - get pointer to the attribute payload
 *
 * This function return a pointer to the attribute payload
 */
void *mnl_attr_get_payload(const struct nlattr *attr)
{
	return (void *)attr + MNL_ATTR_HDRLEN;
}

/**
 * mnl_attr_ok - check if there is room for an attribute in a buffer
 * @nattr: attribute that we want to check if there is room for
 * @len: remaining bytes in a buffer that contains the attribute
 *
 * This function is used to check that a buffer, which is supposed to contain
 * an attribute, has enough room for the attribute that it stores, ie. this
 * function can be used to verify that an attribute is neither malformed nor
 * truncated.
 *
 * This function does not set errno in case of error since it is intended
 * for iterations. Thus, it returns 1 on success and 0 on error.
 *
 * The @len parameter may be negative in the case of malformed messages during
 * attribute iteration, that is why we use a signed integer.
 */
int mnl_attr_ok(const struct nlattr *attr, int len)
{
	return len >= (int)sizeof(struct nlattr) &&
	       attr->nla_len >= sizeof(struct nlattr) &&
	       (int)attr->nla_len <= len;
}

/**
 * mnl_attr_next - get the next attribute in the payload of a netlink message
 * @attr: pointer to the current attribute
 * @len: length of the remaining bytes in the buffer (passed by reference).
 *
 * This function returns a pointer to the next attribute after the one passed
 * as parameter. You have to use mnl_attr_ok() to ensure that the next
 * attribute is valid.
 */
struct nlattr *mnl_attr_next(const struct nlattr *attr, int *len)
{
	*len -= MNL_ALIGN(attr->nla_len);
	return (struct nlattr *)((void *)attr + MNL_ALIGN(attr->nla_len));
}

/**
 * mnl_attr_type_valid - check if the attribute type is valid
 * @attr: pointer to attribute to be checked
 * @max: maximum attribute type
 *
 * This function allows to check if the attribute type is higher than the
 * maximum supported type. If the attribute type is invalid, this function
 * returns -1 and errno is explicitly set. On success, this function returns 1.
 *
 * Strict attribute checking in user-space is not a good idea since you may
 * run an old application with a newer kernel that supports new attributes.
 * This leads to backward compatibility breakages in user-space. Better check
 * if you support an attribute, if not, skip it.
 */
int mnl_attr_type_valid(const struct nlattr *attr, uint16_t max)
{
	if (mnl_attr_get_type(attr) > max) {
		errno = EOPNOTSUPP;
		return -1;
	}
	return 1;
}

static int __mnl_attr_validate(const struct nlattr *attr,
			       enum mnl_attr_data_type type, size_t exp_len)
{
	uint16_t attr_len = mnl_attr_get_payload_len(attr);
	char *attr_data = mnl_attr_get_payload(attr);

	if (attr_len < exp_len) {
		errno = ERANGE;
		return -1;
	}
	switch(type) {
	case MNL_TYPE_FLAG:
		if (attr_len > 0) {
			errno = ERANGE;
			return -1;
		}
		break;
	case MNL_TYPE_NUL_STRING:
		if (attr_len == 0) {
			errno = ERANGE;
			return -1;
		}
		if (attr_data[attr_len-1] != '\0') {
			errno = EINVAL;
			return -1;
		}
		break;
	case MNL_TYPE_STRING:
		if (attr_len == 0) {
			errno = ERANGE;
			return -1;
		}
		break;
	case MNL_TYPE_NESTED:
		/* empty nested attributes are OK. */
		if (attr_len == 0)
			break;
		/* if not empty, they must contain one header, eg. flag */
		if (attr_len < MNL_ATTR_HDRLEN) {
			errno = ERANGE;
			return -1;
		}
		break;
	default:
		/* make gcc happy. */
		break;
	}
	if (exp_len && attr_len > exp_len) {
		errno = ERANGE;
		return -1;
	}
	return 0;
}

/**
 * mnl_attr_validate - validate netlink attribute (simplified version)
 * @attr: pointer to netlink attribute that we want to validate
 * @type: data type (see enum mnl_attr_data_type)
 *
 * The validation is based on the data type. Specifically, it checks that
 * integers (u8, u16, u32 and u64) have enough room for them. This function
 * returns -1 in case of error and errno is explicitly set.
 */
static size_t mnl_attr_data_type_len[MNL_TYPE_MAX] = {
	[MNL_TYPE_U8]		= sizeof(uint8_t),
	[MNL_TYPE_U16]		= sizeof(uint16_t),
	[MNL_TYPE_U32]		= sizeof(uint32_t),
	[MNL_TYPE_U64]		= sizeof(uint64_t),
};

int mnl_attr_validate(const struct nlattr *attr, enum mnl_attr_data_type type)
{
	int exp_len;

	if (type >= MNL_TYPE_MAX) {
		errno = EINVAL;
		return -1;
	}
	exp_len = mnl_attr_data_type_len[type];
	return __mnl_attr_validate(attr, type, exp_len);
}

/**
 * mnl_attr_validate2 - validate netlink attribute (extended version)
 * @attr: pointer to netlink attribute that we want to validate
 * @type: attribute type (see enum mnl_attr_data_type)
 * @exp_len: expected attribute data size
 *
 * This function allows to perform a more accurate validation for attributes
 * whose size is variable. If the size of the attribute is not what we expect,
 * this functions returns -1 and errno is explicitly set.
 */
int mnl_attr_validate2(const struct nlattr *attr, 
		       enum mnl_attr_data_type type, size_t exp_len)
{
	if (type >= MNL_TYPE_MAX) {
		errno = EINVAL;
		return -1;
	}
	return __mnl_attr_validate(attr, type, exp_len);
}

/**
 * mnl_attr_parse - parse attributes
 * @nlh: pointer to netlink message
 * @offset: offset to start parsing from (if payload is after any extra header)
 * @cb: callback function that is called for each attribute
 * @data: pointer to data that is passed to the callback function
 *
 * This function allows to iterate over the sequence of attributes that compose
 * the Netlink message. You can then put the attribute in an array as it
 * usually happens at this stage or you can use any other data structure (such
 * as lists or trees).
 *
 * This function propagates the return value of the callback that can be
 * MNL_CB_ERROR, MNL_CB_OK or MNL_CB_STOP.
 */
int mnl_attr_parse(const struct nlmsghdr *nlh, unsigned int offset,
		   mnl_attr_cb_t cb, void *data)
{
	int ret = MNL_CB_OK;
	struct nlattr *attr = mnl_nlmsg_get_payload_offset(nlh, offset);
	int len = nlh->nlmsg_len - MNL_NLMSG_HDRLEN - MNL_ALIGN(offset);

	while (mnl_attr_ok(attr, len)) {
		if (cb && (ret = cb(attr, data)) <= MNL_CB_STOP)
			return ret;
		attr = mnl_attr_next(attr, &len);
	}
	return ret;
}

/**
 * mnl_attr_parse_nested - parse attributes inside a nest
 * @nested: pointer to netlink attribute that contains a nest
 * @cb: callback function that is called for each attribute in the nest
 * @data: pointer to data passed to the callback function
 *
 * This function allows to iterate over the sequence of attributes that compose
 * the Netlink message. You can then put the attribute in an array as it
 * usually happens at this stage or you can use any other data structure (such
 * as lists or trees).
 *
 * This function propagates the return value of the callback that can be
 * MNL_CB_ERROR, MNL_CB_OK or MNL_CB_STOP.
 */
int mnl_attr_parse_nested(const struct nlattr *nested,
			  mnl_attr_cb_t cb, void *data)
{
	int ret = MNL_CB_OK;
	struct nlattr *attr = mnl_attr_get_payload(nested);
	int len = mnl_attr_get_payload_len(nested);

	while (mnl_attr_ok(attr, len)) {
		if (cb && (ret = cb(attr, data)) <= MNL_CB_STOP)
			return ret;
		attr = mnl_attr_next(attr, &len);
	}
	return ret;
}

/**
 * mnl_attr_get_u8 - returns 8-bit unsigned integer attribute payload
 * @attr: pointer to netlink attribute
 *
 * This function returns the 8-bit value of the attribute payload.
 */
uint8_t mnl_attr_get_u8(const struct nlattr *attr)
{
	return *((uint8_t *)mnl_attr_get_payload(attr));
}

/**
 * mnl_attr_get_u16 - returns 16-bit unsigned integer attribute payload
 * @attr: pointer to netlink attribute
 *
 * This function returns the 16-bit value of the attribute payload.
 */
uint16_t mnl_attr_get_u16(const struct nlattr *attr)
{
	return *((uint16_t *)mnl_attr_get_payload(attr));
}

/**
 * mnl_attr_get_u32 - returns 32-bit unsigned integer attribute payload
 * @attr: pointer to netlink attribute
 *
 * This function returns the 32-bit value of the attribute payload.
 */
uint32_t mnl_attr_get_u32(const struct nlattr *attr)
{
	return *((uint32_t *)mnl_attr_get_payload(attr));
}

/**
 * mnl_attr_get_u64 - returns 64-bit unsigned integer attribute.
 * @attr: pointer to netlink attribute
 *
 * This function returns the 64-bit value of the attribute payload. This
 * function is align-safe since accessing 64-bit Netlink attributes is a
 * common source of alignment issues.
 */
uint64_t mnl_attr_get_u64(const struct nlattr *attr)
{
	uint64_t tmp;
	memcpy(&tmp, mnl_attr_get_payload(attr), sizeof(tmp));
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
	return (const char *)mnl_attr_get_payload(attr);
}

/**
 * mnl_attr_put - add an attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type that you want to add
 * @len: netlink attribute payload length
 * @data: pointer to the data that will be stored by the new attribute
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put(struct nlmsghdr *nlh, uint16_t type,
		  size_t len, const void *data)
{
	struct nlattr *attr = mnl_nlmsg_get_payload_tail(nlh);
	uint16_t payload_len = MNL_ALIGN(sizeof(struct nlattr)) + len;

	attr->nla_type = type;
	attr->nla_len = payload_len;
	memcpy(mnl_attr_get_payload(attr), data, len);
	nlh->nlmsg_len += MNL_ALIGN(payload_len);
}

/**
 * mnl_attr_put_u8 - add 8-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @len: netlink attribute payload size
 * @data: 8-bit unsigned integer data that is stored by the new attribute
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put_u8(struct nlmsghdr *nlh, uint16_t type, uint8_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint8_t), &data);
}

/**
 * mnl_attr_put_u16 - add 16-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: 16-bit unsigned integer data that is stored by the new attribute
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put_u16(struct nlmsghdr *nlh, uint16_t type, uint16_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint16_t), &data);
}

/**
 * mnl_attr_put_u32 - add 32-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: 32-bit unsigned integer data that is stored by the new attribute
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint32_t), &data);
}

/**
 * mnl_attr_put_u64 - add 64-bit unsigned integer attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: 64-bit unsigned integer data that is stored by the new attribute
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t data)
{
	mnl_attr_put(nlh, type, sizeof(uint64_t), &data);
}

/**
 * mnl_attr_put_str - add string attribute to netlink message
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 * @data: pointer to string data that is stored by the new attribute
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put_str(struct nlmsghdr *nlh, uint16_t type, const void *data)
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
 *
 * This function updates the length field of the Netlink message (nlmsg_len)
 * by adding the size (header + payload) of the new attribute.
 */
void mnl_attr_put_str_null(struct nlmsghdr *nlh, uint16_t type, const void *data)
{
	mnl_attr_put(nlh, type, strlen(data)+1, data);
}

/**
 * mnl_attr_nest_start - start an attribute nest
 * @nlh: pointer to the netlink message
 * @type: netlink attribute type
 *
 * This function adds the attribute header that identifies the beginning of
 * an attribute nest. This function always returns a valid pointer to the
 * beginning of the nest.
 */
struct nlattr *mnl_attr_nest_start(struct nlmsghdr *nlh, uint16_t type)
{
	struct nlattr *start = mnl_nlmsg_get_payload_tail(nlh);

	/* set start->nla_len in mnl_attr_nest_end() */
	start->nla_type = NLA_F_NESTED | type;
	nlh->nlmsg_len += MNL_ALIGN(sizeof(struct nlattr));

	return start;
}

/**
 * mnl_attr_nest_end - end an attribute nest
 * @nlh: pointer to the netlink message
 * @start: pointer to the attribute nest returned by mnl_attr_nest_start()
 *
 * This function updates the attribute header that identifies the nest.
 */
void mnl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start)
{
	start->nla_len = mnl_nlmsg_get_payload_tail(nlh) - (void *)start;
}
