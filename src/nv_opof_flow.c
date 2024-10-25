/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 Nvidia
 */
#include "nv_opof.h"

// eth/vlan/ip/udp/gtpu/ip/proto/end
#define MAX_FLOW_ITEM (9)
// mark/age/count/smac/dmac/ttl/vlan/sip/dip/sport/dport/end
#define MAX_ACTION_ITEM (12)

// Used for NAT flow processing
struct proto_flags {
	bool is_ipv4_needed;
	bool is_ipv6_needed;
	bool is_tcp_needed;
	bool is_udp_needed;
};

static struct rte_flow_item eth_item = {
	RTE_FLOW_ITEM_TYPE_ETH,
	0, 0, 0
};

static struct rte_flow_item end_item = {
	RTE_FLOW_ITEM_TYPE_END,
	0, 0, 0
};

struct rte_flow_action_jump fdb_nexthop_group = {
	.group = OPOF_FDB_NEXTHOP_GROUP,
};

struct rte_flow_action_jump nic_rx_group = {
	.group = NIC_RX_GROUP,
};

static struct rte_flow_action end_action = {
	RTE_FLOW_ACTION_TYPE_END,
	0
};

static struct rte_flow_item_ipv4 ipv4_mask = {
	.hdr.next_proto_id = 0xFF,
	.hdr.src_addr = 0xFFFFFFFF,
	.hdr.dst_addr = 0xFFFFFFFF,
};

static struct rte_flow_item_ipv6 ipv6_mask = {
	.hdr.src_addr =
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff",
	.hdr.dst_addr =
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff",
};

static struct rte_flow_item_udp udp_mask = {
	.hdr.src_port = 0xFFFF,
	.hdr.dst_port = 0xFFFF,
};

static struct rte_flow_item_tcp tcp_mask = {
	.hdr.src_port = 0xFFFF,
	.hdr.dst_port = 0xFFFF,
	.hdr.tcp_flags = RTE_TCP_FIN_FLAG |
		RTE_TCP_SYN_FLAG |
		RTE_TCP_RST_FLAG,
};

static int
port_id_is_invalid(portid_t port_id, enum print_warning warning)
{
	uint16_t pid;

	RTE_ETH_FOREACH_DEV(pid)
		if (port_id == pid)
			return 0;

	if (warning == ENABLED_WARN)
		log_error("Invalid port %d", port_id);

	return 1;
}

#define PORT_FLOW_COMPLAIN(err) port_flow_complain(__func__, err)

static int port_flow_complain(const char *func, struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
		[RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
		[RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
	    !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];

	log_error("%s(): Caught PMD error type %d (%s): %s%s: %s", func,
		  error->type, errstr,
		  error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
					   error->cause), buf) : "",
		  error->message ? error->message : "(no stated reason)",
		  rte_strerror(err));
	return -err;
}

struct rte_flow *
nv_opof_add_simple_flow(uint16_t port_id,
		struct rte_flow_attr *attr,
		struct rte_flow_item pattern[],
		struct rte_flow_action actions[],
		const char *flow_name)
{
	struct rte_flow_error error = {};
	struct rte_flow *flow = NULL;

	flow = rte_flow_create(port_id, attr, pattern,
			       actions, &error);

	if (!flow)
		log_error("%s flow creation on port %d failed(0x%x): %s",
		       flow_name, port_id, error.type, error.message ?
		       error.message : "(no stated reason)");

	return flow;
}

int offload_flow_test(portid_t port_id, uint32_t num)
{
	struct rte_flow_item flow_pattern[MAX_FLOW_ITEM];
	struct rte_flow_action actions[MAX_ACTION_ITEM];
	struct rte_flow_action_age age = {};
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item ip_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item tcp_item;
	enum rte_flow_item_type ip_type;
	void *ip_spec, *ip_mask;
	int i = 0, flow_index = 0;
	struct rte_flow **flows;
	uint64_t tic, toc;
	uint32_t rate;
	static struct rte_flow_attr attr = {
		.transfer = 1,
		.group = OPOF_FDB_DEFAULT_GROUP,
		.priority = FDB_FWD_PRIORITY,
	};

	struct rte_flow_action age_action = {
		RTE_FLOW_ACTION_TYPE_AGE,
		&age
	};

	static struct rte_flow_action jump_action = {
		RTE_FLOW_ACTION_TYPE_JUMP,
		&nic_rx_group
	};

	memset(&flow_pattern, 0, sizeof(flow_pattern));

	/* Eth item*/
	flow_pattern[flow_index++] = eth_item;

	/* IP item */
	ip_type = RTE_FLOW_ITEM_TYPE_IPV4;

	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	ipv4_spec.hdr.next_proto_id = IPPROTO_TCP;
	ipv4_spec.hdr.src_addr = 0xc3010102;
	ipv4_spec.hdr.dst_addr = 0xc3010103;
	ip_spec = &ipv4_spec;

	ip_mask = &ipv4_mask;

	ip_item.type = ip_type;
	ip_item.spec = ip_spec;
	ip_item.mask = ip_mask;
	ip_item.last = NULL;

	flow_pattern[flow_index++] = ip_item;

	memset(&tcp_spec, 0, sizeof(tcp_spec));

	tcp_spec.hdr.src_port = 6002;
	tcp_spec.hdr.dst_port = 6003;

	tcp_spec.hdr.tcp_flags = 0;

	tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
	tcp_item.spec = &tcp_spec;
	tcp_item.mask = &tcp_mask;
	tcp_item.last = NULL;

	flow_pattern[flow_index++] = tcp_item;

	flow_pattern[flow_index] = end_item;
	if (flow_index >= MAX_FLOW_ITEM) {
		log_error("Offload flow: flow item overflow");
		return -EINVAL;
	}

	age.timeout = 300;
	actions[i++] = age_action;
	actions[i++] = jump_action;
	actions[i++] = end_action;

	flows = rte_zmalloc("flows",
			    sizeof(struct rte_flow*) * num,
			    RTE_CACHE_LINE_SIZE);

	log_info("Insert flows %d", num);
        tic = rte_rdtsc();
	for (i = 0; i < (int)num; i++) {
		ipv4_spec.hdr.src_addr++;
		flows[i] = rte_flow_create(port_id, &attr, flow_pattern,
					   actions, NULL);
		if (!flows[i])
			break;
	}

        toc = rte_rdtsc() - tic;

	rate = (long double)i * rte_get_tsc_hz() / toc;
	num = i;

	log_info("Destroy flows %d", num);
	for (i = 0; i < (int)num; i++)
		if (flows[i] && rte_flow_destroy(port_id, flows[i], NULL))
			log_error("Failed to destroy flow %u", i);

	log_info("Done");

	rte_free(flows);

	return rate;
}

struct rte_flow *nv_opof_add_vlan_flow(
	uint16_t vlan_id,
	uint16_t pf_port_id,
	uint16_t vf_port_id)
{
	struct rte_flow_attr attr = {
		.transfer = 1,
		.group = OPOF_FDB_DEFAULT_GROUP,
		.priority = FDB_TAGGED_NO_MATCH_PRIORITY,
	};
	struct rte_flow_item_vlan vlan_spec = {
		.tci = RTE_BE16(vlan_id),
	};
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_VLAN, .spec = &vlan_spec, .mask = &rte_flow_item_vlan_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	struct rte_flow_action_count count_action = {};
	struct rte_flow_action_port_id port_action = {
		.id = vf_port_id,
	};
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count_action },
		{ .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &port_action },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	struct rte_flow * flow = nv_opof_add_simple_flow(pf_port_id, &attr, pattern, actions, "vlan_flow");
	return flow;
}

struct session_flow_match_items
{
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item items[MAX_FLOW_ITEM];
	int index;
	bool overflowed;
};

static void insert_match_item(
	struct session_flow_match_items *match, 
	enum rte_flow_item_type item_type, 
	const void *item_spec, 
	const void *item_mask)
{
	if (match->index >= MAX_ACTION_ITEM) {
		match->overflowed = true;
	} else {
		match->items[match->index++] = (struct rte_flow_item) { .type = item_type, .spec = item_spec, .mask = item_mask };
	}
}

struct session_flow_actions
{
	struct rte_flow_action_set_meta meta_conf;
	struct rte_flow_action_age age;
	struct rte_flow_action_count flow_count;
	struct rte_flow_action_set_mac dst_mac;
	struct rte_flow_action_set_mac src_mac;
	struct rte_flow_action_of_set_vlan_vid set_vid;
	struct rte_flow_action_set_ipv4 set_ipv4_src;
	struct rte_flow_action_set_ipv4 set_ipv4_dst;
	struct rte_flow_action_set_ipv6 set_ipv6_src;
	struct rte_flow_action_set_ipv6 set_ipv6_dst;
	struct rte_flow_action_set_tp set_src_port;
	struct rte_flow_action_set_tp set_dst_port;

	struct rte_flow_action actions[MAX_ACTION_ITEM];
	int index;
	bool overflowed;
};

static void insert_action(
	struct session_flow_actions *actions, 
	enum rte_flow_action_type action_type, 
	const void *action_conf)
{
	if (actions->index >= MAX_ACTION_ITEM) {
		actions->overflowed = true;
	} else {
		actions->actions[actions->index++] = (struct rte_flow_action) { .type = action_type, .conf = action_conf };
	}
}

static void populate_session_flow_matches(
	struct fw_session *session,
	enum flow_dir dir,
	struct session_flow_match_items *pattern)
{
	/* Eth item*/
	insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);

	/* Vlan item */
	int vlan_tci = dir == DIR_IN ? session->info.vlan_inLif : session->info.vlan_outLif;
	if (vlan_tci != 0) {
		pattern->vlan_spec.tci = htons(vlan_tci);
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_VLAN, &pattern->vlan_spec, &rte_flow_item_vlan_mask);
	}

	/* Tunnel Item */
	if (session->info.tunnel) {
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_IPV4, NULL, NULL);
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_UDP, NULL, NULL);
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_GTPU, NULL, NULL);
	}

	/* IP item */
	if (session->info.ip_ver == IPPROTO_IP) {
		pattern->ipv4_spec.hdr = (struct rte_ipv4_hdr) {
			.src_addr = htonl(dir==DIR_IN ? session->info.src_ip : session->info.dst_ip),
			.dst_addr = htonl(dir==DIR_IN ? session->info.dst_ip : session->info.src_ip),
			.next_proto_id = session->info.proto,
		};
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_IPV4, &pattern->ipv4_spec, &ipv4_mask);
	} else {
		if (dir == DIR_IN) {
			memcpy(&pattern->ipv6_spec.hdr.src_addr, &session->info.src_ipv6, sizeof(struct in6_addr));
			memcpy(&pattern->ipv6_spec.hdr.dst_addr, &session->info.dst_ipv6, sizeof(struct in6_addr));
		} else {
			memcpy(&pattern->ipv6_spec.hdr.src_addr, &session->info.dst_ipv6, sizeof(struct in6_addr));
			memcpy(&pattern->ipv6_spec.hdr.dst_addr, &session->info.src_ipv6, sizeof(struct in6_addr));
		}
		pattern->ipv6_spec.hdr.proto = session->info.proto;
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_IPV6, &pattern->ipv6_spec, &ipv6_mask);
	}

	/* L4 proto item */
	if (session->info.proto == IPPROTO_UDP) {
		pattern->udp_spec.hdr.src_port = htons(dir==DIR_IN ? session->info.src_port : session->info.dst_port),
		pattern->udp_spec.hdr.dst_port = htons(dir==DIR_IN ? session->info.dst_port : session->info.src_port),
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_UDP, &pattern->udp_spec, &udp_mask);
	} else {
		pattern->tcp_spec.hdr.src_port = htons(dir==DIR_IN ? session->info.src_port : session->info.dst_port),
		pattern->tcp_spec.hdr.dst_port = htons(dir==DIR_IN ? session->info.dst_port : session->info.src_port),
		insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_TCP, &pattern->tcp_spec, &tcp_mask);
	}

	insert_match_item(pattern, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
}

static void update_session_flow_matches_for_nat(
	struct perLinkActionParameters_t *actions,
	struct session_flow_match_items *pattern)
{
	// When SNAT is enabled, the dst matching conditions for DIR_OUT must
	// match the translated SNAT address/port.
	// When DNAT is enabled, the src matching conditions for DIR_OUT must
	// match the translated DNAT address/port.

	if (actions->snatEnable) {
		switch (actions->snat.ipver) {
		case _IPV4:
			pattern->ipv4_spec.hdr.dst_addr = htonl(actions->snat.ipv4.s_addr);
			break;
		case _IPV6:
			memcpy(&pattern->ipv4_spec.hdr.dst_addr, &actions->snat.ipv6, sizeof(struct in6_addr));
			break;
		}
		pattern->udp_spec.hdr.dst_port = htons(actions->snat.port);
		pattern->tcp_spec.hdr.dst_port = htons(actions->snat.port);
	}

	if (actions->dnatEnable) {
		switch (actions->dnat.ipver) {
		case _IPV4:
			pattern->ipv4_spec.hdr.src_addr = htonl(actions->dnat.ipv4.s_addr);
			break;
		case _IPV6:
			memcpy(&pattern->ipv4_spec.hdr.src_addr, &actions->dnat.ipv6, sizeof(struct in6_addr));
			break;
		}
		pattern->udp_spec.hdr.src_port = htons(actions->dnat.port);
		pattern->tcp_spec.hdr.src_port = htons(actions->dnat.port);
	}
}

static void
nv_opof_add_nexthop_nat_actions(
	const struct nat_t *nat,
	struct session_flow_actions *actions,
	bool nat_is_src)
{
	if (nat->ipver == _IPV4) {
		if (nat_is_src) {
			actions->set_ipv4_src.ipv4_addr = htonl(nat->ipv4.s_addr);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC, &actions->set_ipv4_src);
		} else {
			actions->set_ipv4_dst.ipv4_addr = htonl(nat->ipv4.s_addr);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST, &actions->set_ipv4_dst);
		}
	} else { // IPv6
		if (nat_is_src) {
			memcpy(&actions->set_ipv6_src.ipv6_addr, nat->ipv6.s6_addr, 16);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC, &actions->set_ipv6_src);
		} else {
			memcpy(&actions->set_ipv6_dst.ipv6_addr, nat->ipv6.s6_addr, 16);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV6_DST, &actions->set_ipv6_dst);
		}
	}

	if (nat->proto == _UDP) {
		if (nat_is_src) {
			actions->set_src_port.port = htons(nat->port);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_UDP_TP_SRC, &actions->set_src_port);
		} else {
			actions->set_dst_port.port = htons(nat->port);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_UDP_TP_DST, &actions->set_dst_port);
		}
	} else { // TCP
		if (nat_is_src) {
			actions->set_src_port.port = htons(nat->port);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_TCP_TP_SRC, &actions->set_src_port);
		} else {
			actions->set_dst_port.port = htons(nat->port);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_TCP_TP_DST, &actions->set_dst_port);
		}
	}
}

static void populate_session_actions(
	portid_t dest_port_id,
	struct fw_session *session,
	enum flow_dir dir,
	struct offload_flow * p_offload_flow, // used for flow aging context
	struct session_flow_actions *actions)
{
	insert_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, &actions->flow_count);
	
	if (session->actions.action == ACTION_FORWARD) {
		uint32_t mark_port_id = (dest_port_id==portid_pf[0]) ? MARK_PORT_0 : MARK_PORT_1;
		// Note DIR_IN indicates traffic arriving on inLif and leaving on outLif,
		// while DIR_OUT is the reverse.
		// This means DIR_IN associates with out_lif_next_hop, and vice versa.
		struct perLinkActionParameters_t *per_link_actions = (dir==DIR_OUT) ?
			&session->actions.in_lif_params :
			&session->actions.out_lif_params;

		uint32_t mark_next_hop = per_link_actions->nextHopId;
		actions->meta_conf.data = mark_port_id | mark_next_hop;
		actions->meta_conf.mask = 0xffffffff;
		insert_action(actions, RTE_FLOW_ACTION_TYPE_SET_META, &actions->meta_conf);
		
		actions->age.timeout = session->timeout ? session->timeout : DEFAULT_TIMEOUT;
		actions->age.context = p_offload_flow;
		insert_action(actions, RTE_FLOW_ACTION_TYPE_AGE, &actions->age);

		if (per_link_actions->vlan) {
			actions->set_vid.vlan_vid = htons(per_link_actions->vlan);
			insert_action(actions, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID, &actions->set_vid);
		}

		if (per_link_actions->snatEnable) {
			nv_opof_add_nexthop_nat_actions(&per_link_actions->snat, actions, true);
		}
		if (per_link_actions->dnatEnable) {
			nv_opof_add_nexthop_nat_actions(&per_link_actions->dnat, actions, false);
		}

		struct rte_flow_action_jump *jump_dest = mark_next_hop ? &fdb_nexthop_group : &nic_rx_group;
		insert_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump_dest);
	} else {
		insert_action(actions, RTE_FLOW_ACTION_TYPE_DROP, NULL);
	}
	insert_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

int nv_opof_offload_flow_add(
	portid_t port_id,
	portid_t dest_port_id,
	struct fw_session *session,
	enum flow_dir dir,
	bool primary /* vs secondary */)
{
	if (port_id == PORT_ID_INVALID || dest_port_id == PORT_ID_INVALID) {
		return -EINVAL;
	}

	struct offload_flow * p_offload_flow = dir == DIR_IN ?
		(primary ? &session->flow_in  : &session->flow_in_secondary) :
		(primary ? &session->flow_out : &session->flow_out_secondary);
	
	struct session_flow_match_items pattern = {};
	struct session_flow_actions actions = {};

	struct rte_flow_attr attr = {
		.transfer = 1,
		.group = OPOF_FDB_DEFAULT_GROUP,
		.priority = session->actions.action==ACTION_FORWARD ? FDB_FWD_PRIORITY : FDB_DROP_PRIORITY,
	};

	populate_session_flow_matches(session, dir, &pattern);

	populate_session_actions(dest_port_id, session, dir, p_offload_flow, &actions);

	// For dir==IN, the out_lif_params NAT parameters affect the src/dst headers of
	// the packets. For dir==OUT, we need to then match against those header values.
	if (dir == DIR_OUT) {
		update_session_flow_matches_for_nat(&session->actions.out_lif_params, &pattern);
	}

	if (pattern.overflowed) {
		rte_exit(EXIT_FAILURE, "Software error: too many flow match items!");
	}
	if (actions.overflowed) {
		rte_exit(EXIT_FAILURE, "Software error: too many flow actions!");
	}

	struct rte_flow_error flow_error = {};
	struct rte_flow * flow = rte_flow_create(port_id, &attr, pattern.items, actions.actions, &flow_error);
	if (!flow) {
		log_error("Port %d: flow creation failed; error %d:%s", 
			port_id, flow_error.type, flow_error.message);
		return -EINVAL;
	}

	p_offload_flow->session = session;
	p_offload_flow->flow = flow;
	p_offload_flow->portid = port_id;
	rte_atomic32_set(&p_offload_flow->ref_count, 1);

	return 0;
}

int nv_opof_offload_flow_query(portid_t port_id, struct rte_flow *flow,
		       int64_t *packets, int64_t *bytes)
{
	if (port_id == PORT_ID_INVALID) {
		*packets = 0;
		*bytes = 0;
		return 0;
	}

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return -EINVAL;

	struct rte_flow_query_count flow_count = {
		.reset = 0,
		.hits_set = 1,
		.bytes_set = 1,
		.hits = 0,
		.bytes = 0,
	};
	struct rte_flow_action action[2];
	struct rte_flow_error error;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[0].conf = &flow_count;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x55, sizeof(error));

	if (rte_flow_query(port_id, flow, action, &flow_count, &error))
		return PORT_FLOW_COMPLAIN(&error);

	*packets = flow_count.hits;
	*bytes = flow_count.bytes;

	return 0;
}

struct rte_flow *nv_opof_add_nexthop_flow(
	portid_t port_id,
	struct nextHopParameters_t *next_hop)
{
	struct rte_flow_attr attr = {
		.transfer = 1,
		.group = OPOF_FDB_NEXTHOP_GROUP,
	};
	
	struct session_flow_match_items pattern = {};
	struct session_flow_actions actions = {};

	struct rte_flow_item_meta meta_match = { .data = next_hop->nextHopId };
	struct rte_flow_item_meta meta_mask = { .data = MARK_MASK_NEXT_HOP };
	enum rte_flow_item_type ip_item_type = next_hop->ipver==_IPV4 ? 
		RTE_FLOW_ITEM_TYPE_IPV4 : 
		RTE_FLOW_ITEM_TYPE_IPV6;
	insert_match_item(&pattern, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
	insert_match_item(&pattern, ip_item_type, NULL, NULL);
	insert_match_item(&pattern, RTE_FLOW_ITEM_TYPE_META, &meta_match, &meta_mask);

	insert_action(&actions, RTE_FLOW_ACTION_TYPE_COUNT, &actions.flow_count);
	
	if (!off_config_g.overwrite_dst_mac_enabled &&
		next_hop->macRewriteEnable) 
	{
		// apply next-hop smac/dmac
		memcpy(&actions.src_mac.mac_addr, next_hop->macRewrite.srcMac, 6);
		memcpy(&actions.dst_mac.mac_addr, next_hop->macRewrite.dstMac, 6);

		insert_action(&actions, RTE_FLOW_ACTION_TYPE_SET_MAC_DST, &actions.dst_mac);
		insert_action(&actions, RTE_FLOW_ACTION_TYPE_SET_MAC_SRC, &actions.src_mac);
		insert_action(&actions, RTE_FLOW_ACTION_TYPE_DEC_TTL, NULL);
	}
	
	insert_action(&actions, RTE_FLOW_ACTION_TYPE_JUMP, &nic_rx_group);

	insert_match_item(&pattern, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
	insert_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

	if (pattern.overflowed) {
		rte_exit(EXIT_FAILURE, "Software error: too many flow match items!");
	}
	if (actions.overflowed) {
		rte_exit(EXIT_FAILURE, "Software error: too many flow actions!");
	}

	struct rte_flow_error flow_error = {};
	struct rte_flow * flow = rte_flow_create(port_id, &attr, pattern.items, actions.actions, &flow_error);
	if (!flow) {
		log_error("Port %d: next-hop flow creation failed; error %d:%s", 
			port_id, flow_error.type, flow_error.message);
	}
	return flow;
}


const char *pf_flow_names[NUM_PF_FLOWS] = {
	"jump_default_grp",
	"fdb_miss",
	"fdb_miss_alt",
	"to_uplink",
	"hairpin[0]",
	"hairpin[1]",
};

void nv_opof_global_flow_query()
{
	struct rte_flow_action_count count_conf = {};
	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	struct rte_flow_query_count per_flow_count[NUM_PF_FLOWS] = {};
	struct rte_flow_error error;
	uint64_t total_hits = 0;
	struct pf_port_info *port_info = NULL;

	FOREACH_ENABLED_PF(port_info, off_config_g) {
		int port_id = port_info->phy_port;

		for (size_t i=0; i<NUM_PF_FLOWS; i++) {
			struct rte_flow *flow = port_info->flows.flow_ptrs[i];
			if (!flow)
				continue;
			int stat = rte_flow_query(port_id, flow, action, &per_flow_count[i], &error);
			if (stat == 0 && per_flow_count[i].hits_set) {
				total_hits += per_flow_count[i].hits;
			}
		}

		if (port_info->flow_counts == total_hits) {
			continue; // no change; don't log
		}

		port_info->flow_counts = total_hits;

		for (size_t i=0; i<NUM_PF_FLOWS; i++) {
			if (per_flow_count[i].hits_set && per_flow_count[i].hits) {
				log_debug("Global Flows: port %d %s pkts: %ld",
					port_id, pf_flow_names[i], per_flow_count[i].hits);
			}
		}
	}
}

void nv_opof_print_vlan_flows(struct vlan_flow *vlan_flow)
{
	struct rte_flow_query_count flow_count = {};
	struct rte_flow_action action[2] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &flow_count },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_error error;

	for (size_t i=0; i<2; i++) {
		struct rte_flow *flow = vlan_flow->flow[i];
		if (!flow)
			continue;
		int stat = rte_flow_query(portid_pf[i], flow, action, &flow_count, &error);
		if (stat || 
				!flow_count.bytes_set || 
				!flow_count.hits_set || 
				!flow_count.bytes ||
				!flow_count.hits)
			continue;
		log_info("VLAN Flows: port %d VLAN %d VF %d pkts = %ld",
			portid_pf[i], vlan_flow->vlan_id, vlan_flow->vf_index,
			flow_count.hits);
	}
}

void nv_opof_handle_failover(struct pf_port_info * port_info)
{
	if (!port_info->is_enabled || !port_info->is_down) {
		log_warn("Attempting to handle PF%d failover, but enabled=%d, down=%d",
			port_info->pf_num, port_info->is_enabled, port_info->is_down);
		return;
	}

	uint16_t peer_pf = port_info->pf_num ^ 1;
	struct pf_port_info *peer_info = &off_config_g.pf_ports[peer_pf];
	if (!peer_info->is_enabled || peer_info->is_down) {
		log_warn("Attempting to handle PF%d failover, but peer is %s",
			port_info->pf_num, port_info->is_enabled ? "DOWN" : "DISABLED");
		return;
	}

	// For simplicity:
	uint16_t good_portid = peer_info->phy_port;

	pthread_mutex_lock(&off_config_g.ht_lock);

	const void *key = NULL;
	void *data = NULL;
	uint32_t next = 0;
	uint32_t n_sessions_updated = 0;
	uint32_t n_sessions_skipped = 0;
	while (rte_hash_iterate(off_config_g.session_ht, &key, &data, &next) >= 0) {
		struct fw_session *session = data;
		if (session->flow_in.portid == good_portid && session->flow_out.portid == good_portid) 
		{
			++n_sessions_skipped;
			continue; // not affected
		}

		// Flows created on the link that is still up can be updated "in place",
		// while flows created on the failed link must be destroyed and re-created.
		// Stats for destroyed flows are lost.

		nv_opof_offload_flow_destroy(session->flow_in.portid, session->flow_in.flow);
		session->flow_in.portid = good_portid;
		nv_opof_offload_flow_add(session->flow_in.portid, good_portid, session, DIR_IN, true);

		nv_opof_offload_flow_destroy(session->flow_out.portid, session->flow_out.flow);
		session->flow_out.portid = good_portid;
		nv_opof_offload_flow_add(session->flow_out.portid, good_portid, session, DIR_OUT, true);

		++n_sessions_updated;
	}
	log_warn("Transitioned %d sessions from failed PF%d to PF%d; %d sessions were okay",
		n_sessions_updated, port_info->pf_num, peer_info->pf_num, n_sessions_skipped);

	pthread_mutex_unlock(&off_config_g.ht_lock);
}

void nv_opof_check_link_states()
{
	struct pf_port_info *port_info = NULL;
	FOREACH_ENABLED_PF(port_info, off_config_g) {
		struct rte_eth_link link = {};
		rte_eth_link_get(port_info->phy_port, &link);
		bool link_down = link.link_status != RTE_ETH_LINK_UP;
		if (port_info->is_down == link_down) {
			continue;
		}

		log_warn("PF%d: detected link state change from %s to %s",
			port_info->pf_num, port_info->is_down ? "DOWN" : "UP",
			link_down ? "DOWN" : "UP");
		port_info->is_down = link_down;
		port_info->time_port_down = link_down ? rte_get_tsc_cycles() : 0;
		port_info->link_down_handled = false;
	}

	if (off_config_g.port_downtime_threshold_hz != FAILOVER_DISABLED) {
		FOREACH_ENABLED_PF(port_info, off_config_g) {
			if (!port_info->is_down || port_info->link_down_handled)
				continue;
			if (rte_get_tsc_cycles() < port_info->time_port_down + off_config_g.port_downtime_threshold_hz)
				continue;
			nv_opof_handle_failover(port_info);

			// Prevent re-processing this particular link-down event
			port_info->link_down_handled = true;
		}
	}
}

void nv_opof_log_global_flows()
{
	nv_opof_global_flow_query();

#if 0
	// TODO: printing flow queries from this hashtable is buggy
	uint32_t next = 0;
	const void *key = NULL; // not used
	void *data = NULL;
	while (rte_hash_iterate(off_config_g.vlan_flow_ht, key, data, &next) != ENOENT)
	{
		struct vlan_flow *flow = data;
		if (flow)
			nv_opof_print_vlan_flows(flow);
	}
#endif
}

int nv_opof_offload_flow_destroy(portid_t port_id, struct rte_flow *flow)
{
	struct rte_flow_error error;
	int ret = 0;

	if (!flow)
		return 0;

	if (off_config_g.num_pfs == 1 && port_id > 0 ) {
		return 0;
	}

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return -EINVAL;

	memset(&error, 0x33, sizeof(error));
	if (rte_flow_destroy(port_id, flow, &error))
		ret = PORT_FLOW_COMPLAIN(&error);

	return ret;
}

void nv_opof_offload_flow_aged(portid_t port_id)
{
	int nb_context = 0, total = 0, idx;
	struct rte_flow_error error;
	struct fw_session *session, *session_lkup;
	struct offload_flow *flow;
	void **contexts;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	pthread_mutex_lock(&off_config_g.ht_lock);
	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total < 0) {
		PORT_FLOW_COMPLAIN(&error);
		goto unlock;
	}

	if (total == 0)
		goto unlock;

	contexts = rte_zmalloc("aged_ctx", sizeof(void *) * total,
			       RTE_CACHE_LINE_SIZE);
	if (contexts == NULL)
		goto unlock;

	nb_context = rte_flow_get_aged_flows(port_id, contexts,
					     total, &error);
	if (nb_context != total)
		goto free;

	for (idx = 0; idx < nb_context; idx++) {
		rte_atomic32_inc(&off_config_g.stats.age_thread_hb);
		flow = (struct offload_flow *)contexts[idx];
		
		/* Detect the case where the flow shows up in the aged list
		 * but the associated session was deleted in the gRPC thread
		 */
		if (!flow || !flow->session)
			continue;
		session = flow->session;

		rte_atomic32_set(&flow->ref_count, 0);

		ret = rte_hash_lookup_data(off_config_g.session_ht, &session->key.sess_id, (void **)&session_lkup);
		if (ret < 0) {
			// Should not happen, but prevent accessing deleted flows
			log_warn("Skipping deleted session (%lu)", session->key.sess_id);
			continue;
		}

		/* Only delete flow when both directions are aged out.
		 * This hides the bug that the counter on one of the
		 * direction is not updating
		 */
		bool all_flows_timed_out = rte_atomic32_read(&session->flow_in.ref_count) == 0 && 
		                           rte_atomic32_read(&session->flow_out.ref_count) == 0;
		if (off_config_g.is_high_avail) {
			all_flows_timed_out = all_flows_timed_out &&
								  rte_atomic32_read(&session->flow_in_secondary.ref_count) == 0 && 
		                          rte_atomic32_read(&session->flow_out_secondary.ref_count) == 0;
		}
		if (all_flows_timed_out) {
			session->close_code = _TIMEOUT;
			ret = opof_del_flow(session);
			if (!ret)
				rte_atomic32_inc(&off_config_g.stats.aged);
		}
		// Else, leave all flows for this session in place.
		// Note they will be returned by future calls to rte_flow_get_aged_flows().
	}

free:
	rte_free(contexts);
unlock:
	pthread_mutex_unlock(&off_config_g.ht_lock);
}

int nv_opof_offload_flow_flush(portid_t port_id)
{
	struct rte_flow_error error;
	int ret = 0;

	memset(&error, 0x44, sizeof(error));
	if (rte_flow_flush(port_id, &error)) {
		ret = PORT_FLOW_COMPLAIN(&error);
	}

	return ret;
}
