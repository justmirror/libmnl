/*
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include <errno.h>
#include <libmnl/libmnl.h>

static int mnl_cb_noop(const struct nlmsghdr *nlh, void *data)
{
	return MNL_CB_OK;
}

static int mnl_cb_error(const struct nlmsghdr *nlh, void *data)
{
	const struct nlmsgerr *err = mnl_nlmsg_get_data(nlh);

	if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(struct nlmsgerr))) {
		errno = EBADMSG; 
		return MNL_CB_ERROR;
	}
	/* Netlink subsystems returns the errno value with different signess */
	if (err->error < 0)
		errno = -err->error;
	else
		errno = err->error;

	return err->error == 0 ? MNL_CB_STOP : MNL_CB_ERROR;
}

static int mnl_cb_stop(const struct nlmsghdr *nlh, void *data)
{
	return MNL_CB_STOP;
}

static mnl_cb_t default_cb_array[NLMSG_MIN_TYPE] = {
	[NLMSG_NOOP]	= mnl_cb_noop,
	[NLMSG_ERROR]	= mnl_cb_error,
	[NLMSG_DONE]	= mnl_cb_stop,
	[NLMSG_OVERRUN]	= mnl_cb_noop,
};

/**
 * mnl_cb_run2 - callback runqueue for netlink messages
 * @buf: buffer that contains the netlink messages
 * @numbytes: number of bytes stored in the buffer
 * @seq: sequence number that we expect to receive (use zero to skip)
 * @cb_data: callback handler for data messages
 * @data: pointer to data that will be passed to the data callback handler
 * @cb_ctl_array: array of custom callback handlers from control messages
 * @cb_ctl_array_len: length of the array of custom control callback handlers
 *
 * You can set the cb_ctl_array to NULL if you want to use the default control
 * callback handlers, in that case, the parameter cb_ctl_array_len is not
 * checked.
 *
 * This function returns -1 in case of error, 0 if we have received a
 * NLMSG_DONE message or the callback has explicitly returned MNL_CB_STOP.
 */
int mnl_cb_run2(const char *buf, int numbytes, unsigned int seq,
		mnl_cb_t cb_data, void *data,
		mnl_cb_t *cb_ctl_array, int cb_ctl_array_len)
{
	int ret = MNL_CB_OK;
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	while (mnl_nlmsg_ok(nlh, numbytes)) {
		/* perform sequence tracking */
		if (!mnl_nlmsg_seq_ok(nlh, seq)) {
			errno = EILSEQ;
			return -1;
		}

		/* netlink data message handling */
		if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) { 
			if (cb_data){
				ret = cb_data(nlh, data);
				if (ret <= MNL_CB_STOP)
					goto out;
			}
		} else if (nlh->nlmsg_type < cb_ctl_array_len) {
			if (cb_ctl_array && cb_ctl_array[nlh->nlmsg_type]) {
				ret = cb_ctl_array[nlh->nlmsg_type](nlh, data);
				if (ret <= MNL_CB_STOP)
					goto out;
			}
		} else if (default_cb_array[nlh->nlmsg_type]) {
			ret = default_cb_array[nlh->nlmsg_type](nlh, data);
			if (ret <= MNL_CB_STOP)
				goto out;
		}
		nlh = mnl_nlmsg_next(nlh, &numbytes);
	}
out:
	return ret <= MNL_CB_ERROR ? -1 : 0;
}

/**
 * mnl_cb_run - callback runqueue for netlink messages (simplified version)
 * @buf: buffer that contains the netlink messages
 * @numbytes: number of bytes stored in the buffer
 * @seq: sequence number that we expect to receive (use zero to skip)
 * @cb_data: callback handler for data messages
 * @data: pointer to data that will be passed to the data callback handler
 *
 * This function is like mnl_cb_run2() but it does not allow you to set
 * the control callback handlers.
 *
 * This function returns -1 in case of error, 0 if we have received a
 * NLMSG_DONE message or the callback has explicitly returned MNL_CB_STOP.
 */

int mnl_cb_run(const char *buf, int numbytes, unsigned int seq,
	       mnl_cb_t cb_data, void *data)
{
	return mnl_cb_run2(buf, numbytes, seq, cb_data, data, NULL, 0);
}
