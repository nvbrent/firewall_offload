/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "nv_opof.h"

uint16_t nb_rxd = RX_RING_SIZE;
uint16_t nb_txd = TX_RING_SIZE;
queueid_t nb_txq = NUM_REGULAR_Q;
queueid_t nb_rxq = NUM_REGULAR_Q;
// We use 2-4 hairpin queues to improve throughput
queueid_t nb_hpq = NUM_HP_Q;

// Initialize the 2x2 grid of PF hairpin queue pairs.
//
// port_id==pf0:					port_id==pf1:
// P0.rx[1] -> P0.tx[1] (...)		P1.rx[1] -> P0.tx[1] (...)
// P0.rx[N] -> P0.tx[N]				P1.rx[N] -> P0.tx[N]
//
// P0.rx[N+1] -> P1.tx[1] (...)		P1.rx[N+1] -> P1.tx[N+1] (...)
// P0.rx[2N]  -> P1.tx[N]			P1.rx[2N]  -> P1.tx[2N]
//
static int nv_opof_setup_hairpin_queues(portid_t port_id)
{
	uint16_t port_idx = port_id == portid_pf[0] ? 0 : 1;

	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = true,
		.tx_explicit = true,
	};

	for (int peer_idx = 0; peer_idx < MAX_NUM_PF; peer_idx++) {
		hairpin_conf.peers[0].port = portid_pf[peer_idx];

		queueid_t rx_start = nb_rxq + port_idx * nb_hpq;
		queueid_t tx_start = nb_txq + peer_idx * nb_hpq;
		
		for (int i = 0; i < nb_hpq; i++) {
			hairpin_conf.peers[0].queue = rx_start + i;
			int diag = rte_eth_tx_hairpin_queue_setup(
				port_id, tx_start + i, nb_txd, &hairpin_conf);
			if (diag != 0) {
				log_error("Fail to configure port %d TX hairpin "
					"queues %u, err=%d", port_id, i, diag);
				return -1;
			}
		}

		rx_start = nb_rxq + peer_idx * nb_hpq;
		tx_start = nb_txq + port_idx * nb_hpq;

		for (int i = 0; i < nb_hpq; i++) {
			hairpin_conf.peers[0].queue = tx_start + i;
			int diag = rte_eth_rx_hairpin_queue_setup(
				port_id, rx_start + i, nb_rxd, &hairpin_conf);
			if (diag != 0) {
				log_error("Fail to configure port %d RX hairpin "
					"queues %u", port_id, i);
				return -1;
			}
		}

		log_info("Port(%d)/Peer(%d): Set up hairpin (%d..%d) -> (%d..%d)", 
			port_id, hairpin_conf.peers[0].port, 
			rx_start, rx_start + nb_hpq - 1,
			tx_start, tx_start + nb_hpq - 1);
	} 

	return 0;
}

static struct rte_flow *
nv_opof_insert_jump_to_group(
	uint16_t port_id, 
	uint32_t group_id)
{
	// Insert a null-match flow to jump all traffic on the given port from
	// the default group 0 to the specified group.
	struct rte_flow_attr attr = {
		.transfer = 1,
	};
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	struct rte_flow_action_count count_conf = {};
	struct rte_flow_action_jump jump_conf = {
		.group = group_id,
	};
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &jump_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	return nv_opof_add_simple_flow(port_id, &attr, pattern, actions, "JumpToGroup");
}

static struct rte_flow *
nv_opof_create_fdb_miss_flow(uint16_t port_id, portid_t dest_port_id, uint16_t vlan_id, bool enable_vlan_pop)
{
	struct rte_flow_attr attr = {
		.transfer = 1,
		.group = OPOF_FDB_DEFAULT_GROUP,
		.priority = vlan_id ? FDB_TAGGED_NO_MATCH_PRIORITY : FDB_NO_MATCH_PRIORITY,
	};
	struct rte_flow_item_vlan vlan = {
		.tci = RTE_BE16(vlan_id)
	};
	struct rte_flow_item_vlan vlan_mask = {
		.tci = RTE_BE16(0xffff)
	};
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = vlan_id ? RTE_FLOW_ITEM_TYPE_VLAN : RTE_FLOW_ITEM_TYPE_VOID, .spec = &vlan, .mask = &vlan_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	struct rte_flow_action_count count_conf = {};
	struct rte_flow_action_port_id dest_port = {
		.id = dest_port_id,
	};
	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count_conf },
		{ .type = (enable_vlan_pop && vlan_id) ? RTE_FLOW_ACTION_TYPE_OF_POP_VLAN : RTE_FLOW_ACTION_TYPE_VOID },
		{ .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &dest_port },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	return nv_opof_add_simple_flow(port_id, &attr, pattern,
			       action, "Fdb miss");
}

static struct rte_flow *
nv_opof_create_to_uplink_flow(uint16_t port_id, portid_t dest_port_id, uint16_t vlan_id)
{
	struct rte_flow_attr attr = {
		.transfer = 1,
		.group = OPOF_FDB_DEFAULT_GROUP,
		.priority = vlan_id ? FDB_TAGGED_NO_MATCH_PRIORITY : FDB_NO_MATCH_PRIORITY,
	};
	struct rte_flow_action_count count_conf = {};
	struct rte_flow_action_port_id dest_port = {
		.id = dest_port_id,
	};
	struct rte_flow_action_of_push_vlan push_vlan = {
		.ethertype = RTE_BE16(RTE_ETHER_TYPE_VLAN)
	};
	struct rte_flow_action_of_set_vlan_vid set_vlan = {
		.vlan_vid = RTE_BE16(vlan_id),
	};

	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &count_conf },
		{ .type = vlan_id ? RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN : RTE_FLOW_ACTION_TYPE_VOID, .conf = &push_vlan },
		{ .type = vlan_id ? RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID : RTE_FLOW_ACTION_TYPE_VOID, .conf = &set_vlan },
		{ .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &dest_port },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};

	return nv_opof_add_simple_flow(port_id, &attr, pattern,
			       action, "Uplink");
}

static struct rte_flow * 
nv_opof_create_hairpin_flow(
	uint16_t port_id,
	uint32_t mark_id,
	uint32_t hpq_start_idx)
{
	uint16_t hpq_indices[NUM_HP_Q];

	for (int i=0; i<NUM_HP_Q; i++) {
		hpq_indices[i] = hpq_start_idx + i;
	}

	struct rte_flow_action_rss rss_conf = {
		.func = RTE_ETH_HASH_FUNCTION_DEFAULT,
		.level = 0,
		.types = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
		.queue_num = nb_hpq,
		.queue = hpq_indices,
	};
	struct rte_flow_attr attr = {
		.ingress = 1,
		.group = OPOF_NIC_DOMAIN_GROUP,
	};
	struct rte_flow_item_meta meta_conf = {
		.data = mark_id,
	};
	struct rte_flow_item_meta meta_mask = {
		.data = MARK_MASK_PORT_IDS,
	};
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_META, .spec = &meta_conf, .mask = &meta_mask },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
		{ .type = RTE_FLOW_ACTION_TYPE_VOID }, // placeholder for set-src-mac
		{ .type = RTE_FLOW_ACTION_TYPE_VOID }, // placeholder for set-dst-mac
		{ .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	struct rte_flow_action_set_mac set_src_mac = {};
	struct rte_flow_action_set_mac set_dst_mac = {};
	if (off_config_g.overwrite_dst_mac_enabled) {
		// obtain smac from the port, and set dmac according to config
		struct rte_ether_addr mac_addr;
		rte_eth_macaddr_get(port_id, &mac_addr);
		memcpy(set_src_mac.mac_addr, &mac_addr, 6);
		memcpy(set_dst_mac.mac_addr, off_config_g.overwrite_dst_mac.addr_bytes, 6);
		action[1].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
		action[1].conf = &set_src_mac;
		action[2].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
		action[2].conf = &set_dst_mac;
	}

	return nv_opof_add_simple_flow(port_id, &attr, pattern,
			       action, "Hairpin");
}

uint32_t next_sample_session_id = MAX_SESSION;
uint32_t num_sample_flows = 0;

int nv_opof_create_sample_fwd_flow(int proto,
				  enum flow_action action,
				  int dir)
{
	addSessionResponse_t response;
	sessionRequest_t request;
	int ret = 0;

	memset(&response, 0, sizeof(response));
	memset(&request, 0, sizeof(request));

	request.sessId = --next_sample_session_id;
	request.actionParams.actionType = (ACTION_VALUE_T)action;
	request.proto = proto;

	if (dir) {
		++num_sample_flows;
	}

	if (dir) {
		request.inlif = 2;
		request.srcIP.s_addr = 0x10000000 + num_sample_flows; // 16.0.0.1, ...
		request.dstIP.s_addr = 0x30000000 + num_sample_flows; // 48.0.0.1, ...
		//request.dstPort = 5003;
		//request.srcPort = 5002;
		request.srcPort = 53;
		request.dstPort = 53;
	} else {
		request.inlif = 1;
		request.dstIP.s_addr = 0x10000000 + num_sample_flows; // 16.0.0.1
		request.srcIP.s_addr = 0x30000000 + num_sample_flows; // 48.0.0.1
		request.srcPort = 53;
		request.dstPort = 53;
	}

	request.cacheTimeout = 60;

	ret = opof_add_session_server(&request, &response);
	if (!ret)
		log_info("Warnning: Sample flow created for session (%lu) src %x dst %x",
		       request.sessId, request.srcIP.s_addr, request.dstIP.s_addr);

	return ret;
}

int nv_opof_init_flows(struct pf_port_info *port_info)
{
	if (!port_info->is_enabled) {
		return 0;
	}

	// Insert immediate jump for all TCP/UDP traffic to group 1 to work
	// around limitations with group 0. 
	portid_t ports_needing_group_jump[3] = {
		port_info->phy_port,
		port_info->vf_port,
		port_info->vf_alt_port,
	};
	portid_t num_ports_needing_group_jump = sizeof(ports_needing_group_jump)/sizeof(ports_needing_group_jump[0]);
	for (int i=0; i<num_ports_needing_group_jump; i++) {
		portid_t pid = ports_needing_group_jump[i];
		if (pid == PORT_ID_INVALID)
			continue;
		port_info->flows.jump_to_default_group = nv_opof_insert_jump_to_group(
			pid, OPOF_FDB_DEFAULT_GROUP);
		if (!port_info->flows.jump_to_default_group)
			return -EAGAIN;
	}

	// Forward inspected traffic from vport to uplink, optionally inserting a VLAN tag
	portid_t vf_ports[MAX_VF_PER_PF] = {
		port_info->vf_port,
		port_info->vf_alt_port,
	};
	for (int i=0; i<MAX_VF_PER_PF; i++) {
		portid_t pid = vf_ports[i];
		if (pid == PORT_ID_INVALID)
			continue;
		uint16_t vlan_id = off_config_g.vlan_id[i];
		port_info->flows.to_uplink = nv_opof_create_to_uplink_flow(
			pid, port_info->phy_port, vlan_id);
		if (port_info->flows.to_uplink == NULL)
			return -EAGAIN;
	}

	/* RX rule to forward to phy-to-self-hairpin queues (NIC Rx Domain). */
	if (port_info->phy_port != PORT_ID_INVALID) {
		port_info->flows.hairpin[0] = nv_opof_create_hairpin_flow(
			port_info->phy_port, MARK_PORT_0, NUM_REGULAR_Q);
		if (port_info->flows.hairpin[0] == NULL)
			return -EAGAIN;
	}
	
	/* RX rule to forward to phy-to-peer-hairpin queues (NIC Rx Domain). */
	if (port_info->peer_port != PORT_ID_INVALID) {
		port_info->flows.hairpin[1] = nv_opof_create_hairpin_flow(
			port_info->phy_port, MARK_PORT_1, NUM_REGULAR_Q + NUM_HP_Q);
		if (port_info->flows.hairpin[1] == NULL)
			return -EAGAIN;
	}

	/* Default RX rule to forward no-match pkt to vport. */
	if (port_info->vf_port != PORT_ID_INVALID) {
		port_info->flows.fdb_miss = nv_opof_create_fdb_miss_flow(
			port_info->phy_port, 
			port_info->vf_port, 
			off_config_g.vlan_id[0], 
			off_config_g.vlan_access_mode);
		if (!port_info->flows.fdb_miss)
			return -EAGAIN;
	}

	// If there are two distinct vlan IDs, create the second flow to the vf *alternate* port
	if (port_info->vf_alt_port != PORT_ID_INVALID && 
		off_config_g.vlan_id[0] != off_config_g.vlan_id[1]) 
	{
		port_info->flows.fdb_miss_alt = nv_opof_create_fdb_miss_flow(
			port_info->phy_port, 
			port_info->vf_alt_port, 
			off_config_g.vlan_id[1], 
			off_config_g.vlan_access_mode);
		if (!port_info->flows.fdb_miss_alt)
			return -EAGAIN;
	}

	return 0;
}

int nv_opof_port_init(portid_t pid, portid_t peer_pid, struct rte_mempool *mbuf_pool)
{
	if (pid == PORT_ID_INVALID) {
		return 0;
	}

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_lro_pkt_size = RTE_ETHER_MAX_LEN,
		},
		.intr_conf = {
			.lsc = 1, // link-state-change interrupt
		}
	};
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(pid))
		return -EINVAL;

	rte_eth_dev_info_get(pid, &dev_info);

	/* Configure the Ethernet device. */
	uint32_t total_hpq = off_config_g.num_pfs * nb_hpq;
	retval = rte_eth_dev_configure(pid, nb_rxq + total_hpq, nb_txq + total_hpq, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(pid, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet pid. */
	for (q = 0; q < nb_rxq; q++) {
		retval = rte_eth_rx_queue_setup(pid, q, nb_rxd,
				rte_eth_dev_socket_id(pid), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet pid. */
	for (q = 0; q < nb_txq; q++) {
		retval = rte_eth_tx_queue_setup(pid, q, nb_txd,
				rte_eth_dev_socket_id(pid), &txconf);
		if (retval < 0)
			return retval;
	}

	if (peer_pid != PORT_ID_INVALID) {
		retval = nv_opof_setup_hairpin_queues(pid);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet pid. */
	retval = rte_eth_dev_start(pid);
	if (retval < 0) {
		log_error("Can't start eth dev");
		return retval;
	}
	char dev_name[RTE_ETH_NAME_MAX_LEN];
	rte_eth_dev_get_name_by_port(pid, dev_name);
	log_info("Started port %d (%s)", pid, dev_name);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(pid);
	if (retval != 0)
		return retval;

	return 0;
}

int nv_opof_hairpin_bind_port(portid_t pid, portid_t peer_id)
{
	if (pid == PORT_ID_INVALID || peer_id == PORT_ID_INVALID) {
		return 0;
	}

	int diag = rte_eth_hairpin_bind(pid, pid);
	if (diag) {
		log_error("Failed to bind hairpin TX port %u to self: %s",
			 pid, rte_strerror(-diag));
		return diag;
	}

	diag = rte_eth_hairpin_bind(pid, peer_id);
	if (diag) {
		log_error("Failed to bind hairpin TX port %u to %u: %s",
			 pid, peer_id, rte_strerror(-diag));
		return diag;
	}

	diag = rte_eth_hairpin_bind(peer_id, pid);
	if (diag) {
		log_error("Failed to bind hairpin RX port %u to %u: %s",
			 peer_id, pid, rte_strerror(-diag));
		return diag;
	}

	return 0;
}
