/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020-2024 Nvidia
 */

#ifndef NV_OPOF_H
#define NV_OPOF_H

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/cdefs.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ring_elem.h>

#include "opof.h"
#include "opof_serverlib.h"
#include "nv_opof_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NV_OPOF_VERSION "1.7.9"

#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024

#define MAX_NUM_PF (2)
#define MAX_VF_PER_PF (2)

#define MAX_LCORES	(16u)

#define NUM_REGULAR_Q	(1)
#define NUM_HP_Q	(4)

#define MAX_SESSION		(4000000u)
#define MAX_VLAN_FLOWS  (200)
#define MAX_NEXTHOPS  (2000000u)
#define SAMPLE_SESSION_FWD	(MAX_SESSION - 1)
#define SAMPLE_SESSION_DROP	(MAX_SESSION - 2)

#define GRPC_ADDR_SIZE		(32)
#define DEFAULT_GRPC_ADDR	"169.254.33.51"
#define DEFAULT_GRPC_PORT	3443

#define PORT_ID_INVALID ((portid_t)-1)

#define FAILOVER_DISABLED ((uint64_t)-1)

// Note the same 32-bit meta word must carry both the destination
// port ID as well as the next-hop ID.
// We reserve the two upper bits for the Port ID and the lower
// 30 bits for next-hop.
extern uint32_t MARK_MASK_PORT_IDS;
extern uint32_t MARK_MASK_NEXT_HOP;

// Packets marked MARK_PORT_0 will be hairpinned to p0,
// while packets marked MARK_PORT_1 will be hairpinned to p1.
extern uint32_t MARK_PORT_0;
extern uint32_t MARK_PORT_1;

typedef uint16_t queueid_t;
typedef uint16_t portid_t;

extern struct fw_offload_config off_config_g;

// port IDs initialized inside nv_opof_config_init()
extern uint16_t portid_pf[MAX_NUM_PF];
extern uint16_t portid_pf_vf[MAX_NUM_PF][MAX_VF_PER_PF];

#define MAX_DPDK_PORT 6

extern uint16_t INITIATOR_PORT_ID;
extern uint16_t RESPONDER_PORT_ID;

// Note that regardless of priority, FDB (transfer) rules always
// take precedence / execute before NIC (non-transfer) rules.
// When the FDB executes a jump to a non-existing group
// (NIC_RX_GROUP), only then are the NIC-domain rules evaluated.
enum {
	FDB_DROP_PRIORITY     = 1,
	FDB_FWD_PRIORITY      = 2,
	FDB_TAGGED_NO_MATCH_PRIORITY = 3, // IP/Port don't match, but VLAN tag does
	FDB_NO_MATCH_PRIORITY = 4, // No IP/Port match nor VLAN tag
};

enum {
	// The ID of a non-root group in which all application FDB
	// flows will be inserted, because the root group is
	// slower and places more restrictions on priority, etc.
	OPOF_FDB_DEFAULT_GROUP = 1,

	// The ID of a non-root group in which next-hop packet modifications
	// are configured.
	OPOF_FDB_NEXTHOP_GROUP = 2,

	// In the NIC Rx domain, group 0 is sufficient
	OPOF_NIC_DOMAIN_GROUP = 0,

	// The ID of a non-existing FDB flow group.
	// Once a packet lookup reaches this group, it
	// transitions from the FDB domain to the NIC RX domain.
	// From the NIC RX domain, a packet can be hairpin-
	// queued and sent out the uplink port.
	NIC_RX_GROUP = 0xA,
};

enum lcore_type {
	LCORE_TYPE_MIN		= 1,
	LCORE_TYPE_GRPC		= 1,
	LCORE_TYPE_AGING	= 2,
	LCORE_TYPE_MAX		= 3
};

enum {
	/* unit sec */
	DEFAULT_TIMEOUT		= 10,
	MAX_TIMEOUT		= 3275
};

enum print_warning {
	ENABLED_WARN = 0,
	DISABLED_WARN
};

enum flow_action {
	ACTION_DROP	= 0,
	ACTION_FORWARD	= 1
};

enum flow_dir {
	DIR_IN	= 0,
	DIR_OUT	= 1
};

struct lcore_priv {
	enum lcore_type	type;
	uint8_t		id;
};

struct aging_priv {
	uint8_t lcore_id;
};

struct session_info {
	uint32_t inLif;
	uint32_t outLif;
	uint32_t dst_ip;         /**< Dest IPv4 address in big endian. */
	uint32_t src_ip;         /**< Source IPv4 address in big endian. */
	uint8_t dst_ipv6[16];    /**< Dest IPv6 address in big endian. */
	uint8_t src_ipv6[16];    /**< Source IPv6 address in big endian. */
	uint16_t dst_port;       /**< Dest port in big endian. */
	uint16_t src_port;       /**< Source Port in big endian. */
	uint8_t ip_ver;          /**< IP version. */
	uint8_t proto;           /**< L4 Protocol. */
	uint16_t vlan_inLif;
	uint16_t vlan_outLif;
	bool tunnel;             /**< GTPU tunneling */
};

struct session_key {
	uint64_t sess_id;
};

struct action_params {
	enum flow_action action;
	// from opof.h:
	struct perLinkActionParameters_t in_lif_params;
	struct perLinkActionParameters_t out_lif_params;
};

// This structure is passed as the age.context parameter to ensure flows are properly
// aged out and removed, but only after all the flows associated with a session have
// individually timed out.
struct offload_flow {
	struct fw_session *session;
	struct rte_flow *flow;
	rte_atomic32_t ref_count;
	portid_t portid;
};

struct vlan_flow {
	uint16_t vlan_id;
	uint16_t vf_index;
	struct rte_flow *flow[MAX_NUM_PF];
};

struct nexthop_flow {
	uint32_t next_hop_id;

	struct rte_flow *flow[MAX_NUM_PF];
};

struct fw_session {
	struct session_key		key;
	struct session_info		info;
	struct action_params    actions;

	struct offload_flow		flow_in;
	struct offload_flow		flow_out;
	struct offload_flow		flow_in_secondary;
	struct offload_flow		flow_out_secondary;

	uint8_t				state;
	uint8_t				close_code;
	uint32_t			timeout;
};

struct offload_stats {
	rte_atomic32_t active;
	rte_atomic32_t aged;
	rte_atomic32_t zero_in;
	rte_atomic32_t zero_out;
	rte_atomic32_t zero_io;
	rte_atomic32_t client_del;
	rte_atomic32_t age_thread_hb;
	rte_atomic32_t flows_in;
	rte_atomic32_t flows_del;
	rte_atomic32_t flows_get_closed;
	rte_atomic64_t flows_in_maxtsc;
	rte_atomic64_t flows_in_tottsc;
	rte_atomic64_t flows_del_maxtsc;
	rte_atomic64_t flows_del_tottsc;
	rte_atomic64_t flows_get_closed_maxtsc;
	rte_atomic64_t flows_get_closed_tottsc;
};

#define NUM_PF_FLOWS 6 /* max per port */
union pf_flow_pointers
{
	struct {
		struct rte_flow * jump_to_default_group;
		struct rte_flow * fdb_miss;
		struct rte_flow * fdb_miss_alt;
		struct rte_flow * to_uplink;
		struct rte_flow * hairpin[MAX_VF_PER_PF];
	};
	struct rte_flow* flow_ptrs[NUM_PF_FLOWS];
};

struct pf_port_info
{
	bool is_enabled; /**< Whether this PF and its VFs are enabled */
	bool is_down; /**< PF is enabled but link state is down */
	bool link_down_handled; /**< Indicates the link-down status has been processed */
	uint64_t time_port_down; /**< Tracks when a PF entered the down state */
	uint16_t pf_num;
	portid_t phy_port; /**< Port ID of the PF uplink port */
	portid_t peer_port; /**< Port ID of the other PF uplink port; hairpin peer */
	portid_t vf_port; /**< Port ID of the primary VF connected to the vFW */
	portid_t vf_alt_port; /**< Port ID of the secondary VF, or PORT_ID_INVALID if none */

	union pf_flow_pointers flows;
	uint64_t flow_counts;
};

struct fw_offload_config {
	struct lcore_priv	lcores[MAX_LCORES];
	struct aging_priv	aging;
	struct rte_ring		*session_fifo;
	struct rte_hash		*session_ht;
	struct rte_hash		*vlan_flow_ht;
	struct rte_hash		*nexthop_ht;
	pthread_mutex_t		ht_lock;
	struct offload_stats	stats;
	uint64_t            port_downtime_threshold_hz;
	
	bool	 			is_high_avail; /**< rules apply to both PFs, and each PF operates independently */
	
	uint16_t num_pfs; /**< One for single-port; nominally two */
	uint16_t num_reps_per_pf; /**< Number of VFs held by the vFW for each PF. (1 or 2) */
	uint16_t total_num_ports; /**< Used to enumerate new ports as they are probed */

	struct pf_port_info pf_ports[MAX_NUM_PF];

	uint16_t vlan_id[MAX_VF_PER_PF]; /**< when non-zero, specifies the vlan ID for vf_port/vf_alt_port traffic */
	bool     vlan_access_mode; /**< whether to strip VLAN tags going into the VM */

	char grpc_addr[GRPC_ADDR_SIZE];
	uint16_t grpc_port;

	bool overwrite_dst_mac_enabled;
	struct rte_ether_addr overwrite_dst_mac;
};

#define FOREACH_ENABLED_PF(port_info, config) \
	for (port_info = &config.pf_ports[0]; \
		port_info < &config.pf_ports[MAX_NUM_PF]; \
		++port_info) \
  			if (port_info->is_enabled)

int nv_opof_port_init(portid_t pid, portid_t peer_pid, struct rte_mempool *mbuf_pool);
int nv_opof_hairpin_bind_port(portid_t pid, portid_t peer_id);
int nv_opof_init_flows(struct pf_port_info *port_info);
int nv_opof_create_sample_fwd_flow(int proto, enum flow_action action, int dir);

void nv_opof_lcore_init(void);
void nv_opof_clean_up(void);
void nv_opof_force_quit(void);
int nv_opof_thread_mux(void *data __rte_unused);
void nv_opof_stop_aging_thread(void);
void nv_opof_check_link_states(void);
void nv_opof_log_global_flows(void);

struct rte_flow *
nv_opof_add_simple_flow(uint16_t port_id,
		struct rte_flow_attr *attr,
		struct rte_flow_item pattern[],
		struct rte_flow_action actions[],
		const char *flow_name);

int nv_opof_offload_flow_add(
	portid_t port_id,
	portid_t dest_port_id,
	struct fw_session * session,
	enum flow_dir dir,
	bool primary);
int nv_opof_offload_flow_query(portid_t port_id,
		       struct rte_flow *flow,
		       int64_t *packets,
		       int64_t *bytes);
int nv_opof_offload_flow_destroy(portid_t port_id,
			 struct rte_flow *flow);
void nv_opof_offload_flow_aged(portid_t port_id);
int nv_opof_offload_flow_flush(portid_t port_id);

int opof_del_flow(struct fw_session *session);
void opof_del_all_session_server(void);
int _opof_del_session_server(unsigned long sessionId,
			     sessionResponse_t *response);
void opof_del_all_nexthop_sessions(uint32_t next_hop_id);

char *get_session_state(uint8_t state);
char *get_close_code(uint8_t code);
int offload_flow_test(portid_t port_id, uint32_t num);

struct rte_flow *nv_opof_add_vlan_flow(
	uint16_t vlan_id,
	uint16_t pf_port_id, // 1 or 2
	uint16_t vf_port_id); // 1 or 2

struct rte_flow *nv_opof_add_nexthop_flow(
	portid_t port_id,
	struct nextHopParameters_t *next_hop);

bool nv_opof_nexthop_exists(uint32_t next_hop_id);

#ifdef __cplusplus
}
#endif

#endif
