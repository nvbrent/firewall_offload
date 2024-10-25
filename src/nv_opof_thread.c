/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "nv_opof.h"

bool continue_aging_thread = true;

void opof_server(const char *address, unsigned short port, const char* cert, const char* key);

void nv_opof_lcore_init(void)
{
	int i;

	for (i = LCORE_TYPE_MIN; i < LCORE_TYPE_MAX; i++) {
		off_config_g.lcores[i].type = (enum lcore_type)i;
		off_config_g.lcores[i].id = i;
	}

	off_config_g.aging.lcore_id = LCORE_TYPE_AGING;
}

static void nv_opof_aging_thread(uint32_t lcore_id)
{
	long int lwp_id;
	uint32_t i = 0;
	uint16_t nb_ports = rte_eth_dev_count_avail();

	lwp_id = syscall(SYS_gettid);
	log_debug("LCORE(%u) (LWP=%ld): aging thread started",
		  lcore_id, lwp_id);

	while (continue_aging_thread) {
		if ((++i & 0xFFFFF) == 0) {
			rte_atomic32_inc(&off_config_g.stats.age_thread_hb);
			nv_opof_check_link_states();
			nv_opof_log_global_flows();
		}
		if (INITIATOR_PORT_ID < nb_ports) {
			nv_opof_offload_flow_aged(INITIATOR_PORT_ID);
		}
		if (RESPONDER_PORT_ID < nb_ports) {
			nv_opof_offload_flow_aged(RESPONDER_PORT_ID);
		}
	}
}

static void nv_opof_grpc_thread(uint32_t lcore_id)
{
	long int lwp_id;

	lwp_id = syscall(SYS_gettid);
	log_debug("LCORE(%u) (LWP=%ld): grpc thread started at %s:%d",
		 lcore_id, lwp_id,
		 off_config_g.grpc_addr, off_config_g.grpc_port);

	opof_server(off_config_g.grpc_addr, off_config_g.grpc_port,
		    NULL, NULL);
}

int nv_opof_thread_mux(void *data __rte_unused)
{
	char thread_name[RTE_MAX_THREAD_NAME_LEN];
	uint32_t lcore_id = rte_lcore_id();
	const char *thread_name_pattern;
	struct lcore_priv *lcore;
	int ret = 0;

	lcore = &off_config_g.lcores[lcore_id];

	if (unlikely(lcore == NULL)) {
		ret = -1;
		goto err;
	}

	switch(lcore->type)
	{
	case LCORE_TYPE_GRPC:
		thread_name_pattern = "lcore-%u-grpc";
		nv_opof_grpc_thread(lcore_id);
		break;

	case LCORE_TYPE_AGING:
		thread_name_pattern = "lcore-%u-aging";
		nv_opof_aging_thread(lcore_id);
		break;

	case LCORE_TYPE_MAX:
	default:
		thread_name_pattern = "lcore-%u-idle";
		break;
	}

	snprintf(thread_name, sizeof(thread_name),
		 thread_name_pattern, lcore_id);
	thread_name[sizeof(thread_name) - 1] = '\0';
	rte_thread_setname(pthread_self(), thread_name);

	return ret;

err:
	log_error("Thread type %d LCORE %u failed",
		  (int)lcore->type, lcore_id);
	fflush(stdout);
	fflush(stderr);
	exit(EXIT_FAILURE);

	return ret;
}

void nv_opof_stop_aging_thread(void)
{
	continue_aging_thread = false;
}