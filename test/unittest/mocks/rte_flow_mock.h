#ifndef _RTE_FLOW_H
#define _RTE_FLOW_H

#include <rte_flow.h>
#include <functional>

using ut_rte_flow_create_cb = std::function<void(
	uint16_t port_id,
    const struct rte_flow_attr *attr,
    const struct rte_flow_item pattern[],
    const struct rte_flow_action actions[])>;

void
ut_rte_flow_set_flow_create_cb(ut_rte_flow_create_cb create_cb);

int
ut_rte_flow_expect_create_calls(uint32_t calls);

int
ut_rte_flow_teardown(void);

#endif
