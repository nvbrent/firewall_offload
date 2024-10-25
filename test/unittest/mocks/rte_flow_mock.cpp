/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <errno.h>

#include <rte_ethdev.h>
#include <rte_flow.h>

#include <rte_flow_mock.h>

#undef RTE_FLOW_LOG
#define RTE_FLOW_LOG(fmt, ...) fprintf(stderr, "%s " fmt "\n", __func__, __VA_ARGS__)

struct expected_call {
	int calls;
	bool is_active;
};

static uint32_t total_flows;
static struct expected_call flow_create;
static struct expected_call flow_destroy;
static ut_rte_flow_create_cb flow_create_cb;

static void
consume_expected_call(struct expected_call *call)
{
	if (!call->is_active)
		return;

	call->calls--;
}

static bool
is_expected_call_ok(struct expected_call *calls, const char *name)
{
	if (calls->is_active && calls->calls > 0) {
		RTE_FLOW_LOG("%s: exiting with %d calls remaining", name, calls->calls);
		return false;
	}
	return true;
}

struct rte_flow {
	TAILQ_ENTRY(rte_flow) next;
	uint16_t port_id;
	struct rte_flow_template_table *template_table;
	void *user_data;
	bool is_pending_create;
	bool is_pending_destroy;
};

struct port_queue {
	TAILQ_HEAD(, rte_flow) flows;
	uint16_t nr_pending_items;
	uint16_t nr_max_items;
};

struct port_config {
	bool init;
	uint32_t nb_counters;
	uint32_t nb_aging_objects;
	uint32_t nb_meters;
	uint16_t nr_queues;
	struct port_queue *queues;
};

static struct port_config port_cfg[RTE_MAX_ETHPORTS];

static int
verify_flow_attr(const struct rte_flow_attr *attr)
{
	if (attr && (attr->egress + attr->ingress + attr->transfer) != 1)
		return -EINVAL;
	return 0;
}

int
rte_flow_query(uint16_t port_id, struct rte_flow *flow,
	       const struct rte_flow_action *actions, void *data,
	       struct rte_flow_error *flow_err)
{
	return 0;
}

struct rte_flow *
rte_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	struct rte_flow *flow;

	if (verify_flow_attr(attr)) {
		RTE_FLOW_LOG("flow creation invalid attributes (%d, %d, %d) on port %u",
			      attr->egress, attr->ingress, attr->transfer, port_id);
		return NULL;
	}

	consume_expected_call(&flow_create);
	if (flow_create_cb)
		flow_create_cb(port_id, attr, pattern, actions);

	flow = (struct rte_flow*)calloc(1, sizeof(struct rte_flow));
	if (!flow) {
		RTE_FLOW_LOG("failed flow creation on port %u - no memory", port_id);
		return NULL;
	}

	if (error)
		memset(error, 0, sizeof(struct rte_flow_error));
	flow->port_id = port_id;
	total_flows++;
	return flow;
}

int
rte_flow_destroy(uint16_t port_id, struct rte_flow *flow,
		 struct rte_flow_error *error)
{
	consume_expected_call(&flow_destroy);

	if (!flow) {
		RTE_FLOW_LOG("failed flow destroy on port %u - null ptr", port_id);
		return -EINVAL;
	}

	if (flow->port_id != port_id) {
		RTE_FLOW_LOG("failed flow destroy on port %u - created on %u", port_id,
			     flow->port_id);
		return -EINVAL;
	}

	if (error)
		memset(error, 0, sizeof(struct rte_flow_error));

	free(flow);
	total_flows--;
	return 0;
}


int
rte_flow_configure(uint16_t port_id,
		const struct rte_flow_port_attr *port_attr,
		uint16_t nb_queue,
		const struct rte_flow_queue_attr *queue_attr[],
		struct rte_flow_error *error)
{
	struct port_config *port_configure;
	uint16_t queue_id;

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_FLOW_LOG("failed flow configure on port %u - out of range", port_id);
		return -EINVAL;
	}

	if (!port_attr || !queue_attr || nb_queue == 0) {
		RTE_FLOW_LOG("failed flow configure on port %u - invalid params", port_id);
		return -EINVAL;
	}

	port_configure = &port_cfg[port_id];
	if (port_configure->init)
		return 0;

	port_configure->queues = (struct port_queue*)calloc(nb_queue, sizeof(struct port_queue));
	if (!port_configure->queues) {
		RTE_FLOW_LOG("failed flow configure on port %u - no memory", port_id);
		return -ENOMEM;
	}

	for (queue_id = 0; queue_id < nb_queue; queue_id++) {
		struct port_queue *queue = &port_configure->queues[queue_id];

		TAILQ_INIT(&queue->flows);
		queue->nr_pending_items = 0;
		queue->nr_max_items = queue_attr[queue_id]->size;
	}

	port_configure->nb_counters = port_attr->nb_counters;
	port_configure->nb_aging_objects = port_attr->nb_aging_objects;
	port_configure->nb_meters = port_attr->nb_meters;
	port_configure->nr_queues = nb_queue;
	port_configure->init = true;
	return 0;
}



/* UT API */

void
ut_rte_flow_set_flow_create_cb(ut_rte_flow_create_cb create_cb)
{
	flow_create_cb = create_cb;
}

int
ut_rte_flow_expect_create_calls(uint32_t calls)
{
	if (flow_create.is_active && flow_create.calls > 0)
		return -EBADE;

	flow_create.is_active = true;
	flow_create.calls = calls;
	return 0;
}

int
ut_rte_flow_teardown(void)
{
	uint16_t port_id;

	if (!is_expected_call_ok(&flow_create, "flow_create") || !is_expected_call_ok(&flow_destroy, "flow_destroy"))
		return -EBADE;

	// release queues
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		struct port_queue *port_queue;

		if (port_cfg[port_id].init)
			continue;

		port_queue = port_cfg[port_id].queues;
		free(port_queue);
	}

	return 0;
}
