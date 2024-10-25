/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 Nvidia
 */
#include <arpa/inet.h>

#include "nv_opof.h"
#include "nv_opof_rpc.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

const int BF_NETDEV_BUS = 3;
const int BF_NETDEV_DEV = 0;

// Required for FDB-domain mark-action to be later matched in NIC Rx domain
const char *devargs_suffix = ",dv_xmeta_en=2";

extern int cq_timeout_msec;

static struct nv_opof_rpc_context rpc_ctx = {};

struct rte_hash_parameters opof_session_hash_params = {
	.name = "session_ht",
	.entries = MAX_SESSION,
	.key_len = sizeof(struct session_key),
	.hash_func_init_val = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
};

struct rte_hash_parameters opof_vlan_flow_hash_params = {
	.name = "vlan_flow_ht",
	.entries = MAX_VLAN_FLOWS,
	.key_len = sizeof(uint16_t),
	.hash_func_init_val = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
};

struct rte_hash_parameters opof_nexthop_hash_params = {
	.name = "nexthop_ht",
	.entries = MAX_NEXTHOPS,
	.key_len = sizeof(uint32_t),
	.hash_func_init_val = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
};

static uint32_t next_pow2(uint32_t x)
{
	return x == 1 ? 1 : 1 << (64 - __builtin_clzl(x - 1));
}

static void nv_opof_config_init(
	bool high_avail,
	uint16_t num_pfs,
	bool mult_reps_per_pf)
{
	memset(&off_config_g, 0, sizeof(struct fw_offload_config));

	bool single_port = num_pfs==1;

	strcpy(off_config_g.grpc_addr, DEFAULT_GRPC_ADDR);
	off_config_g.grpc_port = DEFAULT_GRPC_PORT;

	off_config_g.port_downtime_threshold_hz = FAILOVER_DISABLED;

	off_config_g.is_high_avail = high_avail;
	off_config_g.num_pfs = num_pfs;
 
	INITIATOR_PORT_ID = portid_pf[0];
	RESPONDER_PORT_ID = portid_pf[1];

	for (int pf=0; pf<MAX_NUM_PF; pf++) {
		struct pf_port_info *port_info = &off_config_g.pf_ports[pf];
		port_info->is_enabled = portid_pf[pf] != PORT_ID_INVALID;

		port_info->pf_num = pf;
		port_info->phy_port = portid_pf[pf];
		port_info->peer_port = single_port ? PORT_ID_INVALID : portid_pf[pf ^ 1];
		port_info->vf_port = portid_pf_vf[pf][0];
		port_info->vf_alt_port = mult_reps_per_pf ? portid_pf_vf[pf][1] : PORT_ID_INVALID;
	}

	pthread_mutex_init(&off_config_g.ht_lock, NULL);
	off_config_g.session_ht = rte_hash_create(&opof_session_hash_params);
	off_config_g.session_fifo = rte_ring_create("sess_fifo",
						    next_pow2(MAX_SESSION), 0, 0);
	off_config_g.vlan_flow_ht = rte_hash_create(&opof_vlan_flow_hash_params);
	off_config_g.nexthop_ht = rte_hash_create(&opof_nexthop_hash_params);
}

static void config_destroy(void)
{
	rte_ring_free(off_config_g.session_fifo);
	rte_hash_free(off_config_g.session_ht);
	rte_hash_free(off_config_g.vlan_flow_ht);
	rte_hash_free(off_config_g.nexthop_ht);
}

void nv_opof_clean_up(void)
{
	portid_t portid;

	nv_opof_stop_aging_thread();
	nv_opof_rpc_stop(&rpc_ctx);
	opof_del_all_session_server();
	config_destroy();

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		nv_opof_offload_flow_flush(portid);
		rte_eth_dev_close(portid);
	}

	log_info("nv_opof closed");
	nv_opof_log_close();
	nv_opof_signal_handler_uninstall();
}

bool probe_pf(int bus, int dev, int pf_num, bool exit_on_failure)
{
	char devargs[256];
	snprintf(devargs, sizeof(devargs), "%02d:%02d.%d%s",
		bus, dev, pf_num, devargs_suffix);
	int stat = rte_dev_probe(devargs);
	
	log_debug("rte_dev_probe(%s) = %d", devargs, stat);
	
	if (stat && exit_on_failure) {
		rte_exit(EXIT_FAILURE, "Failed to rte_dev_probe(%s); error %d", devargs, stat);
	}
	return stat==0;
}

bool probe_vf(int bus, int dev, int pf_num, int representor, bool exit_on_failure)
{
	char devargs[256];
	snprintf(devargs, sizeof(devargs), "%02d:%02d.%d,representor=vf%d%s",
		bus, dev, pf_num, representor, devargs_suffix);
	int stat = rte_dev_probe(devargs);

	log_debug("rte_dev_probe(%s) = %d", devargs, stat);

	if (stat && exit_on_failure) {
		rte_exit(EXIT_FAILURE, "Failed to rte_dev_probe(%s); error %d", devargs, stat);
	}
	return stat==0;
}

void enable_primary_ports(bool allow_single_port, uint16_t * const total_ports)
{
	for (int pf=0; pf<MAX_NUM_PF; pf++) {
		bool allow_fail = allow_single_port && pf>0; // else, abort of failure
		if (!probe_pf(BF_NETDEV_BUS, BF_NETDEV_DEV, pf, !allow_fail)) {
			log_info("Failed to probe p[%d], but ignoring due to allow_single_port", pf);
 			continue;
 		}
 
		portid_pf[pf] = (*total_ports)++;

		probe_vf(BF_NETDEV_BUS, BF_NETDEV_DEV, pf, 0, true);
		portid_pf_vf[pf][0] = (*total_ports)++;
 	}
}
 
bool enable_secondary_vfs(uint16_t * const total_ports)
{
	if (portid_pf_vf[0][1] != PORT_ID_INVALID) {
		log_info("enable_secondary_ports: already enabled");
		return true;
 	}
 
	for (int pf=0; pf<MAX_NUM_PF; pf++) {
		if (!probe_vf(BF_NETDEV_BUS, BF_NETDEV_DEV, pf, 1, false)) {
			log_error("enable_secondary_ports: Failed to enable pf%dvf1", pf);
			return false;
		}
		portid_pf_vf[pf][1] = (*total_ports)++;
	}
	return true;
}

int main(int argc, char *argv[])
{
	int ret;
	bool high_avail = false;
	bool high_avail_requested = false;
	bool allow_single_port = false;
	int samples_flows_to_create = 0;

	nv_opof_log_open();
	sleep(1);

	for (int i=1; i<argc; i++) {
		if (!strcmp(argv[i], "--version")) {
			printf("nv_opof version %s\n", NV_OPOF_VERSION);
			exit(0);
		}
		else if (!strcmp(argv[i], "--console")) {
			nv_opof_log_to_console_enable = true;
		}
		else if (!strcmp(argv[i], "--debug")) {
			nv_opof_set_log_level(LOG_DEBUG);
		}
		else if (!strcmp(argv[i], "--single-port")) {
			allow_single_port = true;
		}
		else if (!strcmp(argv[i], "--high-avail")) {
			high_avail_requested = true;
		}
	}

	/* Initialize the Environment Abstraction Layer (EAL). */
	char *eal_argv[] = { "", "-a00:00.0" };
	int eal_argc = sizeof(eal_argv)/sizeof(eal_argv[0]);
	ret = rte_eal_init(eal_argc, eal_argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	
	enable_primary_ports(allow_single_port, &off_config_g.total_num_ports); // Exits on failure

	bool secondary_vfs_started = enable_secondary_vfs(&off_config_g.total_num_ports); // TODO: handle this from a new gRPC message

	if (high_avail_requested) {
		if (secondary_vfs_started) {
			log_info("Enabling active-active high avail configuration\n");
			high_avail = true;
		} else {
			rte_exit(EXIT_FAILURE, "Insufficient VFs for requested high avail configuration; exiting\n");
		}
	}

	uint16_t nb_ports = rte_eth_dev_count_avail();

	/* Creates a new mempool in memory to hold the mbufs. */
	struct rte_mempool * mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	nv_opof_signal_handler_install();

	log_info("nv_opof started, version %s", NV_OPOF_VERSION);
	
	// TODO: this gets overwritten by config_init() anyway
	ret = nv_opof_config_load(CONFIG_FILE);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot load config file\n");

	int num_pfs = 0;
	for (int pf=0; pf<MAX_NUM_PF; pf++)
		num_pfs += (int)(portid_pf[pf] != PORT_ID_INVALID);

	nv_opof_config_init(high_avail, num_pfs, secondary_vfs_started);

	if (!off_config_g.session_ht) {
		rte_exit(EXIT_FAILURE, "Failed to create hashtable\n");
	}
	if (!off_config_g.session_fifo) {
		rte_exit(EXIT_FAILURE, "Failed to create ring buffer\n");
	}

	for (int i=1; i<argc; i++) {
		if (!strcmp(argv[i], "--grpc")) {
			if (i + 1 < argc && argv[i+1][0] != '-') {
				char *p_colon = strchr(argv[i+1], ':');
				if (p_colon)
					*p_colon = '\0';

				struct in_addr dummy_addr;
				if (inet_pton(AF_INET, argv[i+1], &dummy_addr) == 1) {
					strncpy(off_config_g.grpc_addr, argv[i+1], GRPC_ADDR_SIZE);
				} else {
					rte_exit(EXIT_FAILURE, "Failed to parse GRPC Server addr %s\n", argv[i+1]);
				}
				if (p_colon) {
					off_config_g.grpc_port = atoi(p_colon + 1);
				}
			} else {
				rte_exit(EXIT_FAILURE, "--grpc argument requires [host] or [host:port] argument\n");
			}
		}
		else if (!strcmp(argv[i], "--create_sample")) {
			samples_flows_to_create = 1;
			if (i + 1 < argc && argv[i+1][0] != '-') {
				samples_flows_to_create = atoi(argv[i+1]);
			}
		}
		else if (!strcmp(argv[i], "--dmac")) {
			if (i + 1 < argc) {
				if (rte_ether_unformat_addr(argv[i+1], &off_config_g.overwrite_dst_mac) < 0)
					rte_exit(EXIT_FAILURE, "Failed to parse dst mac: %s\n", argv[i+1]);
				off_config_g.overwrite_dst_mac_enabled = true;
			}
		}
		else if (!strcmp(argv[i], "--vlan")) {
			if (i + 1 < argc) {
				int nmatched = sscanf(argv[i+1], "%hd,%hd", &off_config_g.vlan_id[0], &off_config_g.vlan_id[1]);
				if (nmatched == 1) {
						off_config_g.vlan_id[1] = 0;
				}
			}
		}
		else if (!strcmp(argv[i], "--cq_timeout_msec")) {
			if (i + 1 < argc) {
				cq_timeout_msec = atoi(argv[i+1]);
			}
		}
		else if (!strcmp(argv[i], "--instant-failover")) { // useful for failover testing
			off_config_g.port_downtime_threshold_hz = 0;
		}
		else if (!strcmp(argv[i], "--failover-timeout")) {
			if (i + 1 < argc) {
				double seconds = atof(argv[i+1]);
				off_config_g.port_downtime_threshold_hz = (uint64_t)(seconds * (double)rte_get_timer_hz());
			} else {
				rte_exit(EXIT_FAILURE, "--failover-timeout argument requires [seconds] argument\n");
			}
		}
	}

	/* Initialize all ports. */
	struct pf_port_info *port_info = NULL;
	FOREACH_ENABLED_PF(port_info, off_config_g) {
		if (nv_opof_port_init(port_info->phy_port, port_info->peer_port, mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_info->phy_port);
		}
		if (nv_opof_port_init(port_info->vf_port, PORT_ID_INVALID, mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_info->vf_port);
		}
		if (nv_opof_port_init(port_info->vf_alt_port, PORT_ID_INVALID, mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", port_info->vf_alt_port);
 		}
 	}
 
	FOREACH_ENABLED_PF(port_info, off_config_g) {
		if (nv_opof_hairpin_bind_port(port_info->phy_port, port_info->peer_port) != 0) {
 			rte_exit(EXIT_FAILURE,
				"Cannot bind hairpin port %"PRIu16 "\n",port_info->phy_port);
		}
	}

	FOREACH_ENABLED_PF(port_info, off_config_g) {
		if (nv_opof_init_flows(port_info) != 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot initialize flows on port %d\n", port_info->phy_port);
		}
	}

	for (int i = 0; i < samples_flows_to_create; i++) {
		nv_opof_create_sample_fwd_flow(IPPROTO_UDP, ACTION_FORWARD, true);
		if (!high_avail) {
			nv_opof_create_sample_fwd_flow(IPPROTO_UDP, ACTION_FORWARD, false);
		} // else, for high_avail both directions are always inserted
	}

	nv_opof_lcore_init();

	rte_eal_mp_remote_launch(&nv_opof_thread_mux, NULL, SKIP_MAIN);

	ret = nv_opof_rpc_start(&rpc_ctx);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot enable rpc interface\n");

	rte_eal_mp_wait_lcore();

	return 0;
}
