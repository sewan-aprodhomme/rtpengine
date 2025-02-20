#include "nftables.h"

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "xt_RTPENGINE.h"

#include "helpers.h"




struct iterate_callbacks {
	// called for each expression
	int (*parse_expr)(struct nftnl_expr *e, void *data);

	// called after all expressions have been parsed
	void (*rule_final)(struct nftnl_rule *r, struct iterate_callbacks *);

	// called after all rules have been iterated
	const char *(*iterate_final)(struct mnl_socket *nl, int family, const char *chain,
			uint32_t *seq, struct iterate_callbacks *);

	// common arguments
	const char *chain;
	const char *base_chain;

	// scratch area for rule callbacks, set to zero for every rule
	union {
		struct {
			bool match_immediate:1;
		};
	} rule_scratch;

	// scratch area for rule iterating
	union {
		struct {
			GQueue handles;
		};
	} iterate_scratch;
};

struct add_rule_callbacks {
	const char *(*callback)(struct nftnl_rule *, int family, struct add_rule_callbacks *);
	const char *chain;
	const char *base_chain;
	int table;

	// intermediate storage area
	struct xt_rtpengine_info rtpe_target_info;
};



static void expr_free(struct nftnl_expr **e) {
	if (*e)
		nftnl_expr_free(*e);
}
static void rule_free(struct nftnl_rule **r) {
	if (*r)
		nftnl_rule_free(*r);
}
static void chain_free(struct nftnl_chain **c) {
	if (*c)
		nftnl_chain_free(*c);
}
static void table_free(struct nftnl_table **t) {
	if (*t)
		nftnl_table_free(*t);
}


static int match_immediate_rtpe(struct nftnl_expr *e, void *data) {
	struct iterate_callbacks *callbacks = data;

	uint32_t len;
	const char *n = nftnl_expr_get(e, NFTNL_EXPR_NAME, &len);
	// match jumps to our configured chain
	if (!strcmp(n, "immediate")) {
		n = nftnl_expr_get(e, NFTNL_EXPR_IMM_CHAIN, &len);
		if (n && !strcmp(n, callbacks->chain))
			callbacks->rule_scratch.match_immediate = true;
	}
	// and also match top-level targets
	else if (!strcmp(n, "target")) {
		n = nftnl_expr_get(e, NFTNL_EXPR_TG_NAME, &len);
		if (n && !strcmp(n, "RTPENGINE"))
			callbacks->rule_scratch.match_immediate = true;
	}
	return 0;
}


static void check_immediate(struct nftnl_rule *r, struct iterate_callbacks *callbacks) {
	if (!callbacks->rule_scratch.match_immediate)
		return;

	uint64_t handle = nftnl_rule_get_u64(r, NFTNL_RULE_HANDLE);
	g_queue_push_tail(&callbacks->iterate_scratch.handles, g_slice_dup(uint64_t, &handle));
}


static int nftables_do_rule(const struct nlmsghdr *nlh, void *data) {
	struct iterate_callbacks *callbacks = data;

	AUTO_CLEANUP(struct nftnl_rule *r, rule_free) = nftnl_rule_alloc();
	if (!r)
		return MNL_CB_ERROR;

	if (nftnl_rule_nlmsg_parse(nlh, r) < 0)
		return MNL_CB_OK;

	if (nftnl_expr_foreach(r, callbacks->parse_expr, callbacks) < 0)
		return MNL_CB_OK;

	callbacks->rule_final(r, callbacks);

	return MNL_CB_OK;
}


static const char *__read_response(struct mnl_socket *nl, uint32_t seq, mnl_cb_t cb_data, void *data,
		const char *err1, const char *err2)
{
	uint32_t portid = mnl_socket_get_portid(nl);
	char buf[MNL_SOCKET_BUFFER_SIZE];

	while (true) {
		int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (ret < 0)
			return err1;
		if (ret == 0)
			break;

		ret = mnl_cb_run(buf, ret, 0, portid, cb_data, data);
		if (ret < 0)
			return err2;
		if (ret == 0)
			break;
	}

	return NULL;
}

// macro for customised error strings
#define read_response(instance, ...) __read_response(__VA_ARGS__, \
		"failed to receive from netlink socket for " instance, \
	"error returned from netlink for " instance)


static const char *iterate_rules(struct mnl_socket *nl, int family, const char *chain,
		uint32_t *seq,
		struct iterate_callbacks callbacks)
{
	AUTO_CLEANUP(struct nftnl_rule *r, rule_free) = nftnl_rule_alloc();
	if (!r)
		return "failed to allocate rule for iteration";

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, "filter");
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
			NLM_F_DUMP, *seq);

	nftnl_rule_nlmsg_build_payload(nlh, r);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		return "failed to write to netlink socket for iteration";

	const char *err = read_response("iterate rules", nl, *seq, nftables_do_rule, &callbacks);
	if (err)
		return err;

	err = callbacks.iterate_final(nl, family, chain, seq, &callbacks);
	if (err)
		return err;

	return NULL;
}


static bool set_rule_handle(struct nftnl_rule *r, void *data) {
	uint64_t *handle = data;
	nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, *handle);
	return true;
}


typedef union {
			void (*rule_fn)(struct nlmsghdr *nlh, struct nftnl_rule *t);
			void (*generic_fn)(struct nlmsghdr *nlh, void *);
} test;

static const char *__batch_request(struct mnl_socket *nl, int family, uint32_t *seq,
		uint16_t type, uint16_t flags,
		union {
			void (*table_fn)(struct nlmsghdr *, const struct nftnl_table *);
			void (*rule_fn)(struct nlmsghdr *, struct nftnl_rule *);
			void (*chain_fn)(struct nlmsghdr *, const struct nftnl_chain *);
			void (*generic_fn)(struct nlmsghdr *, void *);
		}  __attribute__ ((__transparent_union__)) build_payload,
		void *ptr,
		const char *err1, const char *err2, const char *err3)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	nftnl_batch_begin(mnl_nlmsg_batch_current(batch), (*seq)++);
	mnl_nlmsg_batch_next(batch);

	uint32_t req_seq = *seq;
	struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			type, family,
			flags | NLM_F_ACK, (*seq)++);
	build_payload.generic_fn(nlh, ptr);
	mnl_nlmsg_batch_next(batch);

	nftnl_batch_end(mnl_nlmsg_batch_current(batch), (*seq)++);
	mnl_nlmsg_batch_next(batch);

	if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0)
		return err1;

	mnl_nlmsg_batch_stop(batch);

	return __read_response(nl, req_seq, NULL, NULL, err2, err3);
}

// macro for customised error strings
#define batch_request(instance, ...) __batch_request(__VA_ARGS__, \
		"failed to write to netlink socket for " instance, \
		"failed to receive from netlink socket for " instance, \
		"error returned from netlink for " instance)


static const char *delete_rules(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq,
		bool (*callback)(struct nftnl_rule *r, void *data), void *data)
{
	AUTO_CLEANUP(struct nftnl_rule *r, rule_free) = nftnl_rule_alloc();
	if (!r)
		return "failed to allocate rule for deletion";

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, "filter");
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain);

	if (callback) {
		if (!callback(r, data))
			return NULL;
	}

	return batch_request("delete rule", nl, family, seq, NFT_MSG_DELRULE, 0,
			nftnl_rule_nlmsg_build_payload, r);
}



static const char *iterate_delete_rules(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq,
		struct iterate_callbacks *callbacks)
{

	while (callbacks->iterate_scratch.handles.length) {
		uint64_t *handle = g_queue_pop_head(&callbacks->iterate_scratch.handles);
		// transfer to stack and free
		uint64_t h = *handle;
		g_slice_free(uint64_t, handle);

		const char *err = delete_rules(nl, family, chain, seq, set_rule_handle, &h);
		if (err)
			return err;
	}
	return NULL;
}


static void nftables_socket_close(struct mnl_socket **nl) {
	if (*nl)
		mnl_socket_close(*nl);
}


static const char *local_input_chain(struct nftnl_chain *c) {
	nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, NF_INET_LOCAL_IN);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, 0);
	nftnl_chain_set_u32(c, NFTNL_CHAIN_POLICY, NF_ACCEPT);
	return NULL;
}


static const char *add_chain(struct mnl_socket *nl, int family, const char *chain, uint32_t *seq,
		const char *(*callback)(struct nftnl_chain *))
{
	AUTO_CLEANUP(struct nftnl_chain *c, chain_free) = nftnl_chain_alloc();
	if (!c)
		return "failed to allocate chain for adding";

	nftnl_chain_set_u32(c, NFTNL_RULE_FAMILY, family);
	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, "filter");
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);

	if (callback) {
		const char *err = callback(c);
		if (err)
			return err;
	}

	return batch_request("add chain", nl, family, seq, NFT_MSG_NEWCHAIN, NLM_F_CREATE,
			nftnl_chain_nlmsg_build_payload, c);
}


static const char *add_rule(struct mnl_socket *nl, int family, uint32_t *seq,
		struct add_rule_callbacks callbacks)
{
	struct nftnl_rule *r = nftnl_rule_alloc();
	if (!r)
		return "failed to allocate rule for adding";

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, "filter");

	const char *err = callbacks.callback(r, family, &callbacks);
	if (err)
		return err;

	return batch_request("add rule", nl, family, seq, NFT_MSG_NEWRULE, NLM_F_APPEND | NLM_F_CREATE,
			nftnl_rule_nlmsg_build_payload, r);
}


static const char *input_immediate(struct nftnl_rule *r, int family, struct add_rule_callbacks *callbacks) {
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, callbacks->base_chain);

	AUTO_CLEANUP(struct nftnl_expr *e, expr_free) = nftnl_expr_alloc("payload");
	if (!e)
		return "failed to allocate payload expr for immediate";

	uint8_t proto = IPPROTO_UDP;

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
	if (family == NFPROTO_IPV4)
		nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, protocol));
	else if (family == NFPROTO_IPV6)
		nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct ip6_hdr, ip6_nxt));
	else
		return "unsupported address family for immediate";
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, sizeof(proto));

	nftnl_rule_add_expr(r, e);
	e = NULL;

	e = nftnl_expr_alloc("cmp");
	if (!e)
		return "failed to allocate cmp expr for immediate";

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, &proto, sizeof(proto));

	nftnl_rule_add_expr(r, e);
	e = NULL;

	e = nftnl_expr_alloc("counter");
	if (!e)
		return "failed to allocate counter expr for immediate";
	nftnl_rule_add_expr(r, e);
	e = NULL;

	e = nftnl_expr_alloc("immediate");
	if (!e)
		return "failed to allocate immediate expr";

	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, 0);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, NFT_JUMP);
	nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, callbacks->chain);

	nftnl_rule_add_expr(r, e);
	e = NULL;

	return NULL;
}


static const char *rtpe_target(struct nftnl_rule *r, int family, struct add_rule_callbacks *callbacks) {
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, callbacks->chain);

	AUTO_CLEANUP(struct nftnl_expr *e, expr_free) = nftnl_expr_alloc("target");
	if (!e)
		return "failed to allocate target expr for RTPENGINE";

	nftnl_expr_set_str(e, NFTNL_EXPR_TG_NAME, "RTPENGINE");
	nftnl_expr_set_u32(e, NFTNL_EXPR_TG_REV, 0);

	callbacks->rtpe_target_info = (struct xt_rtpengine_info) { .id = callbacks->table };

	nftnl_expr_set(e, NFTNL_EXPR_TG_INFO, &callbacks->rtpe_target_info, sizeof(callbacks->rtpe_target_info));

	nftnl_rule_add_expr(r, e);
	e = NULL;

	e = nftnl_expr_alloc("counter");
	if (!e)
		return "failed to allocate counter expr for RTPENGINE";
	nftnl_rule_add_expr(r, e);
	e = NULL;

	return NULL;
}


static const char *delete_chain(struct mnl_socket *nl, int family, uint32_t *seq, const char *chain) {
	AUTO_CLEANUP(struct nftnl_chain *c, chain_free) = nftnl_chain_alloc();
	if (!c)
		return "failed to allocate chain for deletion";

	nftnl_chain_set_u32(c, NFTNL_RULE_FAMILY, family);
	nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, "filter");
	nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);

	return batch_request("delete chain", nl, family, seq, NFT_MSG_DELCHAIN, 0,
			nftnl_chain_nlmsg_build_payload, c);
}


static const char *nftables_shutdown_family(struct mnl_socket *nl, int family, uint32_t *seq,
		const char *chain, const char *base_chain, void *data)
{
	// clean up rules in legacy `INPUT` chain
	const char *err = iterate_rules(nl, family, "INPUT", seq,
			(struct iterate_callbacks) {
				.parse_expr = match_immediate_rtpe,
				.chain = chain,
				.rule_final = check_immediate,
				.iterate_final = iterate_delete_rules,
			});
	if (err)
		return err;

	// clean up rules in `input` chain
	err = iterate_rules(nl, family, "input", seq,
			(struct iterate_callbacks) {
				.parse_expr = match_immediate_rtpe,
				.chain = chain,
				.rule_final = check_immediate,
				.iterate_final = iterate_delete_rules,
			});
	if (err)
		return err;

	if (base_chain) {
		// clean up rules in other base chain chain if any
		err = iterate_rules(nl, family, base_chain, seq,
				(struct iterate_callbacks) {
					.parse_expr = match_immediate_rtpe,
					.chain = chain,
					.rule_final = check_immediate,
					.iterate_final = iterate_delete_rules,
				});
		if (err)
			return err;
	}

	// clear out custom chain if it already exists
	err = delete_rules(nl, family, chain, seq, NULL, NULL);
	if (err) {
		if (errno != ENOENT) // ignore trying to delete stuff that doesn't exist
			return err;
	}

	err = delete_chain(nl, family, seq, chain);
	if (err) {
		if (errno != ENOENT) // ignore trying to delete stuff that doesn't exist
			return err;
	}

	return NULL;
}


static const char *add_table(struct mnl_socket *nl, int family, uint32_t *seq) {
	AUTO_CLEANUP(struct nftnl_table *t, table_free) = nftnl_table_alloc();
	if (!t)
		return "failed to allocate table";

	nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
	nftnl_table_set_str(t, NFTNL_TABLE_NAME, "filter");

	return batch_request("add table", nl, family, seq, NFT_MSG_NEWTABLE, NLM_F_CREATE,
			nftnl_table_nlmsg_build_payload, t);
}


static const char *nftables_setup_family(struct mnl_socket *nl, int family, uint32_t *seq,
		const char *chain, const char *base_chain, void *data)
{
	const char *err = nftables_shutdown_family(nl, family, seq, chain, base_chain, NULL);
	if (err)
		return err;

	// create the table in case it doesn't exist
	err = add_table(nl, family, seq);
	if (err)
		return err;

	if (base_chain) {
		// make sure we have a local input base chain
		err = add_chain(nl, family, base_chain, seq, local_input_chain);
		if (err)
			return err;

		// add custom chain
		err = add_chain(nl, family, chain, seq, NULL);
		if (err)
			return err;

		// add jump rule from input base chain to custom chain
		err = add_rule(nl, family, seq, (struct add_rule_callbacks) {
				.callback = input_immediate,
				.chain = chain,
				.base_chain = base_chain,
			});
		if (err)
			return err;
	}
	else {
		// create custom base chain
		err = add_chain(nl, family, chain, seq, local_input_chain);
		if (err)
			return err;
	}

	// add rule for kernel forwarding
	int *table = data;
	return add_rule(nl, family, seq, (struct add_rule_callbacks) {
			.callback = rtpe_target,
			.chain = chain,
			.table = *table,
		});
}


static const char *nftables_do(const char *chain, const char *base_chain,
		const char *(*do_func)(struct mnl_socket *nl, int family, uint32_t *seq,
			const char *chain, const char *base_chain, void *data),
		void *data)
{
	if (!chain || !chain[0])
		return NULL;
	if (!base_chain[0])
		base_chain = NULL;

	AUTO_CLEANUP(struct mnl_socket *nl, nftables_socket_close) = mnl_socket_open(NETLINK_NETFILTER);
	if (!nl)
		return "failed to open netlink socket";

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return "failed to bind netlink socket";

	uint32_t seq = time(NULL);

	const char *err = do_func(nl, NFPROTO_IPV4, &seq, chain, base_chain, data);
	if (err)
		return err;
	err = do_func(nl, NFPROTO_IPV6, &seq, chain, base_chain, data);
	if (err)
		return err;

	return NULL;
}


const char *nftables_setup(const char *chain, const char *base_chain, int table) {
	return nftables_do(chain, base_chain, nftables_setup_family, &table);
}

const char *nftables_shutdown(const char *chain, const char *base_chain) {
	return nftables_do(chain, base_chain, nftables_shutdown_family, NULL);
}
