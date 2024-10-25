/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <stdlib.h>
#include <time.h>

#include <rte_cycles.h>

#include "opof.h"
#include "opof_error.h"
#include "opof_serverlib.h"
#include "opof_test_util.h"

#include "nv_opof.h"

char *get_session_state(uint8_t state)
{
	switch(state)
	{
	case 0:
		return "EST";
	case 1:
		return "CLS_1";
	case 2:
		return "CLS_2";
	case 3:
		return "CLOSED";
	default:
		return "UNKOWN";
	}
}

char *get_close_code(uint8_t code)
{
	switch(code)
	{
	case 0:
		return "NA";
	case 1:
		return "FINACK";
	case 2:
		return "RST";
	case 3:
		return "AGE_OUT";
	default:
		return "UNKOWN";
	}
}

static void display_response(sessionResponse_t *response,
			     char *cmd)
{
	log_debug("\n" "CMD        " "ID        "
	       "IN_PACKETS   IN_BYTES      OUT_PACKETS  OUT_BYTES     "
	       "STATE   " "CLOSE   " "\n"
	       "%-11s"
	       "%-10lu"
	       "%-13lu" "%-14lu" "%-13lu" "%-14lu"
	       "%-8s" "%-8s" "\n",
	       cmd, response->sessionId,
	       response->inPackets,
	       response->inBytes,
	       response->outPackets,
	       response->outBytes,
	       get_session_state(response->sessionState),
	       get_close_code(response->sessionCloseCode));
}

static void display_request(sessionRequest_t *request,
			    char *cmd)
{
	if (request->ipver == _IPV6) {
		request->srcIP.s_addr = 0;
		request->dstIP.s_addr = 0;
	}

	log_debug("CMD  " "ID        IN  OUT  VLAN-IN VLAN-OUT  "
		  "SRC_IPv4         SRC_PORT  DST_IPv4         DST_PORT  "
		  "PROTO  IP  ACT  AGE");
	log_debug(
		  "%-5s" "%-10lu" "%-4u" "%-5u" "%-8u" "%-10u"
		  "%03u.%03u.%03u.%03u  " "%-10u" "%03u.%03u.%03u.%03u  "
		  "%-10u" "%-7s" "%-4u" "%-5s" "%-4u",
		  cmd, request->sessId,
		  request->inlif,
		  request->outlif,
		  request->vlan_inLif,
		  request->vlan_outLif,
		  (request->srcIP.s_addr >> 24) & 0xFF,
		  (request->srcIP.s_addr >> 16) & 0xFF,
		  (request->srcIP.s_addr >> 8) & 0xFF,
		  request->srcIP.s_addr & 0xFF,
		  request->srcPort,
		  (request->dstIP.s_addr >> 24) & 0xFF,
		  (request->dstIP.s_addr >> 16) & 0xFF,
		  (request->dstIP.s_addr >> 8) & 0xFF,
		  request->dstIP.s_addr & 0xFF,
		  request->dstPort,
		  request->proto == 6 ? "TCP" : "UDP",
		  request->ipver == _IPV4 ? 4 : 6,
		  request->actionParams.actionType == _FORWARD ? "FWD" : "DROP",
		  request->cacheTimeout);

	if (request->ipver == _IPV6)
		log_debug("\n"
			  "srcIPv6: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
			  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
			  "dstIPv6: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
			  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			  request->srcIPV6.s6_addr[0],
			  request->srcIPV6.s6_addr[1],
			  request->srcIPV6.s6_addr[2],
			  request->srcIPV6.s6_addr[3],
			  request->srcIPV6.s6_addr[4],
			  request->srcIPV6.s6_addr[5],
			  request->srcIPV6.s6_addr[6],
			  request->srcIPV6.s6_addr[7],
			  request->srcIPV6.s6_addr[8],
			  request->srcIPV6.s6_addr[9],
			  request->srcIPV6.s6_addr[10],
			  request->srcIPV6.s6_addr[11],
			  request->srcIPV6.s6_addr[12],
			  request->srcIPV6.s6_addr[13],
			  request->srcIPV6.s6_addr[14],
			  request->srcIPV6.s6_addr[15],
			  request->dstIPV6.s6_addr[0],
			  request->dstIPV6.s6_addr[1],
			  request->dstIPV6.s6_addr[2],
			  request->dstIPV6.s6_addr[3],
			  request->dstIPV6.s6_addr[4],
			  request->dstIPV6.s6_addr[5],
			  request->dstIPV6.s6_addr[6],
			  request->dstIPV6.s6_addr[7],
			  request->dstIPV6.s6_addr[8],
			  request->dstIPV6.s6_addr[9],
			  request->dstIPV6.s6_addr[10],
			  request->dstIPV6.s6_addr[11],
			  request->dstIPV6.s6_addr[12],
			  request->dstIPV6.s6_addr[13],
			  request->dstIPV6.s6_addr[14],
			  request->dstIPV6.s6_addr[15]);
}

int opof_get_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));
	response->sessionId = sessionId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (ret < 0) {
		log_debug("no such session (%lu)", sessionId);
		return _NOT_FOUND;
	}

	nv_opof_offload_flow_query(session->flow_in.portid, session->flow_in.flow,
			   &response->inPackets, &response->inBytes);

	nv_opof_offload_flow_query(session->flow_out.portid, session->flow_out.flow,
			   &response->outPackets, &response->outBytes);

	if (off_config_g.is_high_avail) {
		struct sessionResponseTuple temp_response = {};

		nv_opof_offload_flow_query(session->flow_in_secondary.portid, session->flow_in_secondary.flow,
				&temp_response.inPackets, &temp_response.inBytes);

		nv_opof_offload_flow_query(session->flow_out_secondary.portid, session->flow_out_secondary.flow,
				&temp_response.outPackets, &temp_response.outBytes);
		
		response->inPackets  += temp_response.inPackets;
		response->inBytes    += temp_response.inBytes;
		response->outPackets += temp_response.outPackets;
		response->outBytes   += temp_response.outBytes;
	}
	response->sessionState = session->state;
	response->sessionCloseCode = session->close_code;

	return _OK;
}

static void opof_get_session_stats(struct fw_session *session,
				   sessionResponse_t *response)
{
	response->sessionId = session->key.sess_id;

	nv_opof_offload_flow_query(session->flow_in.portid, session->flow_in.flow,
			   &response->inPackets, &response->inBytes);

	nv_opof_offload_flow_query(session->flow_out.portid, session->flow_out.flow,
			   &response->outPackets, &response->outBytes);

	if (off_config_g.is_high_avail) {
		struct sessionResponseTuple temp_response;

		nv_opof_offload_flow_query(session->flow_in_secondary.portid, session->flow_in_secondary.flow,
				&temp_response.inPackets, &temp_response.inBytes);

		nv_opof_offload_flow_query(session->flow_out_secondary.portid, session->flow_out_secondary.flow,
				&temp_response.outPackets, &temp_response.outBytes);
		
		response->inPackets  += temp_response.inPackets;
		response->inBytes    += temp_response.inBytes;
		response->outPackets += temp_response.outPackets;
		response->outBytes   += temp_response.outBytes;
	}

	if (!response->inPackets)
		rte_atomic32_inc(&off_config_g.stats.zero_in);
	if (!response->outPackets)
		rte_atomic32_inc(&off_config_g.stats.zero_out);
	if (!response->inPackets && !response->outPackets)
		rte_atomic32_inc(&off_config_g.stats.zero_io);

	response->sessionState = session->state;
	response->sessionCloseCode = session->close_code;
}

int opof_del_flow(struct fw_session *session)
{
	struct rte_hash *ht = off_config_g.session_ht;
	sessionResponse_t *session_stat;
	uint64_t tic, toc;
	int pos;

	tic = rte_rdtsc();

	session->state = _CLOSED;
	session_stat = rte_zmalloc("stats",
				   sizeof(sessionResponse_t),
				   RTE_CACHE_LINE_SIZE);
	if (session_stat) {
		opof_get_session_stats(session, session_stat);
	} else {
		log_error("failed to allocate session stat");
	}
	log_debug("session %lu: in-hits: %lu out-hits: %lu", 
		session_stat->sessionId, session_stat->inPackets, session_stat->outPackets);

	nv_opof_offload_flow_destroy(session->flow_in.portid, session->flow_in.flow);
	nv_opof_offload_flow_destroy(session->flow_out.portid, session->flow_out.flow);

	if (off_config_g.is_high_avail) {
		nv_opof_offload_flow_destroy(session->flow_in_secondary.portid, session->flow_in_secondary.flow);
		nv_opof_offload_flow_destroy(session->flow_out_secondary.portid, session->flow_out_secondary.flow);
	}

	pos = rte_hash_del_key(ht, &session->key);
	if (pos < 0)
		log_warn("no such session (%lu)", session->key.sess_id);
	else
		rte_hash_free_key_with_position(ht, pos);

	if (session_stat && rte_ring_enqueue(off_config_g.session_fifo, session_stat))
		log_error("no enough room in session session_fifo");

	memset(session, 0, sizeof(struct fw_session));
	rte_free(session);

	rte_atomic32_dec(&off_config_g.stats.active);

	toc = (rte_rdtsc() - tic) * 1000000 / rte_get_tsc_hz();
	if (toc > (uint64_t)rte_atomic64_read(&off_config_g.stats.flows_del_maxtsc))
		rte_atomic64_set(&off_config_g.stats.flows_del_maxtsc, toc);
	rte_atomic64_add(&off_config_g.stats.flows_del_tottsc, toc);
	rte_atomic32_inc(&off_config_g.stats.flows_del);

	return 0;
}

int opof_add_session_server(sessionRequest_t *parameters,
			    addSessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	uint64_t tic, toc;
	int ret;
	int i;
	int flow_result[4] = { 0, 0, 0, 0 };
	(void)response;

	memset(&key, 0, sizeof(key));

	display_request(parameters, "add");

	tic = rte_rdtsc();

	key.sess_id = parameters->sessId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (ret >= 0) {
		log_warn("Session (%lu) already exists", key.sess_id);
		return _ALREADY_EXISTS;
	}

	uint32_t next_hop_ids[] = {
		parameters->actionParams.actionParams_inLif.nextHopId,
		parameters->actionParams.actionParams_outLif.nextHopId,
	};
	for (i=0; i<2; i++) {
		if (next_hop_ids[i] == 0)
			continue;
		if (!nv_opof_nexthop_exists(next_hop_ids[i])) {
			log_warn("Session (%lu) next hop %u does not exist", key.sess_id, next_hop_ids[i]);
			return _FAILED_PRECONDITION;
		}
	}

	session = rte_zmalloc("session",
			      sizeof(struct fw_session),
			      RTE_CACHE_LINE_SIZE);
	if (!session) {
		log_error("failed to allocate session");
		return _RESOURCE_EXHAUSTED;
	}

	session->key.sess_id = parameters->sessId;

	session->info.src_ip = parameters->srcIP.s_addr;
	session->info.dst_ip = parameters->dstIP.s_addr;
	if (parameters->ipver == _IPV6) {
		memcpy(&session->info.src_ipv6, &parameters->srcIPV6.s6_addr, sizeof(struct in6_addr));
		memcpy(&session->info.dst_ipv6, &parameters->dstIPV6.s6_addr, sizeof(struct in6_addr));
	}
	session->info.src_port = parameters->srcPort;
	session->info.dst_port = parameters->dstPort;
	session->info.ip_ver = parameters->ipver == _IPV4 ? IPPROTO_IP : IPPROTO_IPV6;
	session->info.proto = parameters->proto;
	session->info.tunnel = parameters->encapType == _GTPU;
	session->info.vlan_inLif = parameters->vlan_inLif;
	session->info.vlan_outLif = parameters->vlan_outLif;

	session->actions.action = (enum flow_action)parameters->actionParams.actionType;

	session->actions.in_lif_params = parameters->actionParams.actionParams_inLif;
	session->actions.out_lif_params = parameters->actionParams.actionParams_outLif;

	if (parameters->cacheTimeout >= MAX_TIMEOUT) {
		log_info("WARNING: "
			 "requested timeout(%u), max(%u), use default(%u)",
			 parameters->cacheTimeout, MAX_TIMEOUT,
			 DEFAULT_TIMEOUT);
		session->timeout = DEFAULT_TIMEOUT;
	} else {
		session->timeout = parameters->cacheTimeout;
	}

	if (off_config_g.num_pfs == 1) {
		// overwrite the portid assignments when single_port enabled
		parameters->inlif = 1;
		parameters->outlif = 1;
	}

	if (off_config_g.is_high_avail) {
		session->flow_in.portid = INITIATOR_PORT_ID;
		session->flow_out.portid = INITIATOR_PORT_ID;
		session->flow_in_secondary.portid = RESPONDER_PORT_ID;
		session->flow_out_secondary.portid = RESPONDER_PORT_ID;
	} else {
		session->flow_in.portid  = parameters->inlif==1  ? INITIATOR_PORT_ID : RESPONDER_PORT_ID;
		session->flow_out.portid = parameters->outlif==1 ? INITIATOR_PORT_ID : RESPONDER_PORT_ID;
	}

	pthread_mutex_lock(&off_config_g.ht_lock);

	flow_result[0] = nv_opof_offload_flow_add(
		session->flow_in.portid, 
		session->flow_out.portid, 
		session, DIR_IN, true);
	flow_result[1] = nv_opof_offload_flow_add(
		session->flow_out.portid, 
		session->flow_in.portid, 
		session, DIR_OUT, true);

	if (off_config_g.is_high_avail) {
		flow_result[2] = nv_opof_offload_flow_add(
			session->flow_in_secondary.portid, 
			session->flow_in_secondary.portid, // same
			session, DIR_IN, false);
		flow_result[3] = nv_opof_offload_flow_add(
			session->flow_out_secondary.portid, 
			session->flow_out_secondary.portid, // same
			session, DIR_OUT, false);
	}

	for (i=0; i<4; i++) {
		if (flow_result[i] != 0) {
			log_error("ERR(%d): Failed to add session (%lu) flow in",
				flow_result[i], session->key.sess_id);
			ret = _INTERNAL;
			goto out;
		}
	}

	ret = rte_hash_add_key_data(ht, &session->key,
					(void *)session);
	if (ret < 0) {
		log_error("Failed to add sessiion (%lu) to ht",
				session->key.sess_id);
		ret = _INTERNAL;
		goto out;
	}

	session->state = _ESTABLISHED;
	rte_atomic32_inc(&off_config_g.stats.active);

	toc = (rte_rdtsc() - tic) * 1000000 / rte_get_tsc_hz();
	if (toc > (uint64_t)rte_atomic64_read(&off_config_g.stats.flows_in_maxtsc))
		rte_atomic64_set(&off_config_g.stats.flows_in_maxtsc, toc);
	rte_atomic64_add(&off_config_g.stats.flows_in_tottsc, toc);
	rte_atomic32_inc(&off_config_g.stats.flows_in);

	pthread_mutex_unlock(&off_config_g.ht_lock);
	return _OK;

out:
	nv_opof_offload_flow_destroy(session->flow_out.portid, session->flow_out.flow);
	nv_opof_offload_flow_destroy(session->flow_in.portid, session->flow_in.flow);
	nv_opof_offload_flow_destroy(session->flow_out_secondary.portid, session->flow_out_secondary.flow);
	nv_opof_offload_flow_destroy(session->flow_in_secondary.portid, session->flow_in_secondary.flow);
	rte_free(session);
	pthread_mutex_unlock(&off_config_g.ht_lock);
	return ret;
}

int opof_del_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));
	response->sessionId = sessionId;

	pthread_mutex_lock(&off_config_g.ht_lock);
	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (ret < 0) {
		pthread_mutex_unlock(&off_config_g.ht_lock);
		return _NOT_FOUND;
	}
	ret = opof_del_flow(session);
	pthread_mutex_unlock(&off_config_g.ht_lock);
	if (!ret)
		rte_atomic32_inc(&off_config_g.stats.client_del);

	return ret ? _INTERNAL : _OK;
}

void opof_del_all_session_server(void)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	const void *next_key = NULL;
	uint32_t iter = 0;
	int ret;

	log_info("Delete all sessions");

	pthread_mutex_lock(&off_config_g.ht_lock);
	while (rte_hash_iterate(ht, &next_key,
				(void **)&session, &iter) >= 0) {
		ret = opof_del_flow(session);
		if (!ret)
			rte_atomic32_inc(&off_config_g.stats.client_del);
	}
	pthread_mutex_unlock(&off_config_g.ht_lock);
}

// Delete all sessions which reference next_hop_id.
// If next_hop_id == 0, then delete any sessions which
// reference *any* next_hop_id.
void opof_del_all_nexthop_sessions(uint32_t next_hop_id)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	const void *next_key = NULL;
	uint32_t iter = 0;
	int ret;

	log_info("Delete all sessions");

	pthread_mutex_lock(&off_config_g.ht_lock);
	while (rte_hash_iterate(ht, &next_key,
				(void **)&session, &iter) >= 0) {
		if (!session->actions.in_lif_params.nextHopId && 
			!session->actions.out_lif_params.nextHopId) {
			continue; // not a next-hop-enabled flow
		}
		if (next_hop_id == 0 || 
			session->actions.in_lif_params.nextHopId == next_hop_id || 
			session->actions.out_lif_params.nextHopId == next_hop_id) {
			ret = opof_del_flow(session);
			if (!ret)
				rte_atomic32_inc(&off_config_g.stats.client_del);
		}
	}
	pthread_mutex_unlock(&off_config_g.ht_lock);
}

int opof_get_closed_sessions_server(statisticsRequestArgs_t *request,
				    sessionResponse_t responses[])
{
	int size = request->pageSize;
	int deq, count, i;
	uint64_t tic, toc;
	sessionResponse_t **session_stats;

	tic = rte_rdtsc();

	count = rte_ring_count(off_config_g.session_fifo);

	size = MIN(MIN(size, count), BUFFER_MAX);

	if (!size)
		return 0;

	session_stats = rte_zmalloc("temp",
				    sizeof(sessionResponse_t *) * size,
				    RTE_CACHE_LINE_SIZE);
	if (!session_stats) {
		log_error("failed to allocate session stats, size = %d", size);
		return 0;
	}

	deq = rte_ring_dequeue_bulk(off_config_g.session_fifo,
				    (void **)session_stats, size,
				    NULL);
	if (deq) {
		for (i = 0; i < deq; i++) {
			memcpy(&responses[i], session_stats[i],
			       sizeof(sessionResponse_t));
			display_response(&responses[i], "get_close");

			rte_free(session_stats[i]);
		}
	}

	rte_free(session_stats);

	toc = (rte_rdtsc() - tic) * 1000000 / rte_get_tsc_hz();
	if (toc > (uint64_t)rte_atomic64_read(&off_config_g.stats.flows_get_closed_maxtsc))
		rte_atomic64_set(&off_config_g.stats.flows_get_closed_maxtsc, toc);
	rte_atomic64_add(&off_config_g.stats.flows_get_closed_tottsc, toc);
	rte_atomic32_inc(&off_config_g.stats.flows_get_closed);

	return deq;
}

int opof_get_all_sessions_server(
	int pageSize, 
	uint64_t *startSession,
	int pageCount, 
	sessionResponse_t **responses)
{
	(void)pageSize;
	(void)startSession;
	(void)pageCount;
	(void)responses;
	return _OK;
}

int opof_add_vlan_flow_server(uint16_t vlan_id, uint16_t vf_index_1_or_2)
{
	struct vlan_flow * vlan_flow_entry = NULL;
	int ret = rte_hash_lookup_data(off_config_g.vlan_flow_ht, &vlan_id, (void **)&vlan_flow_entry);
	if (ret >= 0) {
		log_warn("VLAN Flow for VLAN ID (%u) already exists", vlan_id);
		return _ALREADY_EXISTS;
	}

	vlan_flow_entry = rte_zmalloc("vlan_flow_entry", sizeof(struct vlan_flow), RTE_CACHE_LINE_SIZE);
	if (!vlan_flow_entry) {
		log_error("Failed to allocate vlan_flow_entry");
		goto cleanup;
	}

	vlan_flow_entry->vlan_id  = vlan_id;
	vlan_flow_entry->vf_index = vf_index_1_or_2;

	uint16_t vf_index = vf_index_1_or_2 == 2 ? 1 : 0;

	for (int i=0; i<off_config_g.num_pfs; i++) {
		log_info("Forwarding VLAN %d from port %d to port %d", 
			vlan_id, portid_pf[i], portid_pf_vf[i][vf_index]);
		vlan_flow_entry->flow[i] = nv_opof_add_vlan_flow(
			vlan_id, portid_pf[i], portid_pf_vf[i][vf_index]);

		if (!vlan_flow_entry->flow[i]) {
			log_error("Failed to create flow for port %d VLAN ID %d", i, vlan_id);
			goto cleanup;
		}
	}

	ret = rte_hash_add_key_data(off_config_g.vlan_flow_ht, &vlan_flow_entry->vlan_id, vlan_flow_entry);
	if (ret < 0) {
		log_error("Failed to add vlan_flow for VLAN ID (%u) to ht", vlan_flow_entry->vlan_id);
		goto cleanup;
	}

	return 0;

cleanup:
	if (vlan_flow_entry) {
		for (int i=0; i<MAX_NUM_PF; i++) {
			if (vlan_flow_entry->flow[i]) {
				struct rte_flow_error err = {};
				rte_flow_destroy(portid_pf[i], vlan_flow_entry->flow[i], &err);
				if (err.type != RTE_FLOW_ERROR_TYPE_NONE) {
					log_error("Failed to destroy flow for port %d VLAN ID %d", i, vlan_id);
				}
			}
		}
		rte_free(vlan_flow_entry);
	}
	return _RESOURCE_EXHAUSTED;
}

size_t opof_get_vlan_flow_count_server()
{
	return rte_hash_count(off_config_g.vlan_flow_ht);
}

int opof_get_vlan_flows_server(uint16_t *vlan_ids, uint16_t *vf_indices, size_t vlanFlowMaxCount, size_t *vlanFlowActualCount)
{
	size_t nVlansCopied = 0;

	const void *key = NULL;
	void *data = NULL;
	uint32_t next = 0;
	while (nVlansCopied < vlanFlowMaxCount) {
		int it = rte_hash_iterate(off_config_g.vlan_flow_ht, &key, &data, &next);
		if (it < 0 || !key || !data)
			break;

		const struct vlan_flow * vlan_flow_entry = data;
		vlan_ids[nVlansCopied] = vlan_flow_entry->vlan_id;
		vf_indices[nVlansCopied] = vlan_flow_entry->vf_index;
		++nVlansCopied;
	}

	if (vlanFlowActualCount)
		*vlanFlowActualCount = nVlansCopied;

	return 0;
}

int opof_remove_vlan_flow_server(uint16_t vlan_id)
{
	struct vlan_flow * vlan_flow_entry = NULL;
	int ret = rte_hash_lookup_data(off_config_g.vlan_flow_ht, &vlan_id, (void **)&vlan_flow_entry);
	if (ret < 0) {
		log_warn("VLAN Flow for VLAN ID (%u) does not exist", vlan_id);
		return _NOT_FOUND;
	}

	struct rte_flow_query_count flow_count = {};
	struct rte_flow_error error;
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &flow_count },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	for (int i=0; i<MAX_NUM_PF; i++) {
		if (portid_pf[i] == PORT_ID_INVALID)
			continue;

		if (vlan_flow_entry->flow[i]) {
			// Retrieve stats for vlan flow before destroying it
			if (rte_flow_query(portid_pf[i], vlan_flow_entry->flow[i], actions, &flow_count, &error)) {
				log_warn("VLAN Flow: failed to query stats on port %d: %s",
					portid_pf[i], error.message);
			}

			rte_flow_destroy(portid_pf[i], vlan_flow_entry->flow[i], &error);
			if (error.type != RTE_FLOW_ERROR_TYPE_NONE) {
				log_warn("VLAN Flow destroy failed on port %d: %s",
					portid_pf[i], error.message);
			}
		}
		log_info("No longer forwarding VLAN %d on port %d; total hits: %lu", 
			vlan_flow_entry->vlan_id, portid_pf[i], flow_count.hits);
	}

	int it = rte_hash_del_key(off_config_g.vlan_flow_ht, &vlan_id);
	if (it >= 0) {
		rte_hash_free_key_with_position(off_config_g.vlan_flow_ht, it);
	}
	rte_free(vlan_flow_entry);

	return 0;
}

int opof_clear_vlan_flows_server()
{
	const void *key = NULL;
	void *data = NULL;
	while (true) {
		uint32_t next = 0;
		int it = rte_hash_iterate(off_config_g.vlan_flow_ht, &key, &data, &next);
		if (it<0 || !key || !data)
			break;
		const struct vlan_flow * vlan_flow_entry = data;
		opof_remove_vlan_flow_server(vlan_flow_entry->vlan_id);
	}
	return 0;
}

bool nv_opof_nexthop_exists(uint32_t next_hop_id)
{
	struct nexthop_flow * entry = NULL;
	int ret = rte_hash_lookup_data(off_config_g.nexthop_ht, &next_hop_id, (void **)&entry);
	return ret >= 0;
}

int opof_set_next_hop_server(struct nextHopParameters_t *nextHop)
{
	if (nextHop->nextHopId == 0) {
		log_warn("NextHop: invalid ID: %u. Must be > 0.", nextHop->nextHopId);
		return _INVALID_ARGUMENT;
	}
	
	if ((nextHop->nextHopId & MARK_MASK_NEXT_HOP) != nextHop->nextHopId) {
		log_warn("NextHop: invalid ID: %u. Must be < %u.", nextHop->nextHopId, MARK_MASK_PORT_IDS);
		return _INVALID_ARGUMENT;
	}
	
	struct nexthop_flow * prev_entry = NULL;
	int ret = rte_hash_lookup_data(off_config_g.nexthop_ht, &nextHop->nextHopId, (void **)&prev_entry);
	if (ret >= 0) {
		log_info("Updating NextHop %u", nextHop->nextHopId);
	} else {
		log_info("Inserting NextHop %u", nextHop->nextHopId);
	}

	struct nexthop_flow * nexthop_entry = rte_zmalloc("nexthop_entry", sizeof(struct nexthop_flow), RTE_CACHE_LINE_SIZE);
	if (!nexthop_entry) {
		log_error("Failed to allocate nexthop_entry");
		goto cleanup;
	}

	nexthop_entry->next_hop_id = nextHop->nextHopId;

	for (int i=0; i<off_config_g.num_pfs; i++) {
		if (portid_pf[i] != PORT_ID_INVALID) {
			nexthop_entry->flow[i] = nv_opof_add_nexthop_flow(portid_pf[i], nextHop);
			if (!nexthop_entry->flow[i]) {
				log_error("Failed to create flow for port %d next hop ID %d", i, nexthop_entry->next_hop_id);
				goto cleanup;
			}
		}
	}

	if (prev_entry) {
		// now that we have inserted the new entries, delete the old ones
		struct rte_flow_error error = {};
		for (int i=0; i<off_config_g.num_pfs; i++) {
			if (portid_pf[i] != PORT_ID_INVALID) {
				rte_flow_destroy(portid_pf[i], prev_entry->flow[i], &error);
			}
		}
		// update the hashtable entry
		memcpy(prev_entry, nexthop_entry, sizeof(struct nexthop_flow));
	} else {
		ret = rte_hash_add_key_data(off_config_g.nexthop_ht, &nexthop_entry->next_hop_id, nexthop_entry);
		if (ret < 0) {
			log_error("Failed to add next hop ID (%u) to ht", nexthop_entry->next_hop_id);
			goto cleanup;
		}
	}

	return 0;

cleanup:
	if (nexthop_entry) {
		for (int i=0; i<MAX_NUM_PF; i++) {
			if (nexthop_entry->flow[i]) {
				struct rte_flow_error err = {};
				rte_flow_destroy(portid_pf[i], nexthop_entry->flow[i], &err);
				if (err.type != RTE_FLOW_ERROR_TYPE_NONE) {
					log_error("Failed to destroy flow for port %d next hop %d", i, nexthop_entry->next_hop_id);
				}
			}
		}
		rte_free(nexthop_entry);
	}
	return _RESOURCE_EXHAUSTED;
}

int opof_destroy_next_hop_flow(struct nexthop_flow * nexthop_entry)
{
	uint32_t next_hop_id = nexthop_entry->next_hop_id;

	struct rte_flow_query_count flow_count = {};
	struct rte_flow_error error;
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT, .conf = &flow_count },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	
	for (int i=0; i<MAX_NUM_PF; i++) {
		if (portid_pf[i] == PORT_ID_INVALID || nexthop_entry->flow[i] == NULL)
			continue;

		// Retrieve stats for nexthop flow before destroying it			
		if (rte_flow_query(portid_pf[i], nexthop_entry->flow[i], actions, &flow_count, &error)) {
			log_warn("NextHop Flow: failed to query stats on port %d: %s",
				portid_pf[i], error.message);
		}

		int ret = rte_flow_destroy(portid_pf[i], nexthop_entry->flow[i], &error);
		if (ret) {
			log_warn("NextHop Flow destroy failed on port %d: %s",
				portid_pf[i], error.message);
		}

		log_info("NextHop %u on port %d removed; total hits: %lu", 
			next_hop_id, portid_pf[i], flow_count.hits);
	}

	int it = rte_hash_del_key(off_config_g.nexthop_ht, &next_hop_id);
	if (it >= 0) {
		rte_hash_free_key_with_position(off_config_g.nexthop_ht, it);
	}
	rte_free(nexthop_entry);

	return 0;
}

int opof_destroy_next_hop_server(uint32_t next_hop_id)
{
	struct nexthop_flow * nexthop_entry = NULL;
	int ret = rte_hash_lookup_data(off_config_g.nexthop_ht, &next_hop_id, (void **)&nexthop_entry);
	if (ret < 0) {
		log_warn("NextHop for ID (%u) does not exist", next_hop_id);
		return _NOT_FOUND;
	}

	opof_del_all_nexthop_sessions(next_hop_id);

	return opof_destroy_next_hop_flow(nexthop_entry);
}

int opof_clear_next_hops_server()
{
	log_info("Delete all next hops");

	opof_del_all_nexthop_sessions(0);

	struct nexthop_flow *nexthop_entry = NULL;
	const void *next_key = NULL;
	uint32_t iter = 0;
	while (rte_hash_iterate(off_config_g.nexthop_ht, &next_key, (void **)&nexthop_entry, &iter) >= 0) {
		(void)opof_destroy_next_hop_flow(nexthop_entry);
	}
	return 0;
}

int opof_get_version(
    char * vendor_out,    size_t vendorMaxLength,
    char * name_out,      size_t nameMaxLength,
    char * version_out,   size_t versionMaxLength,
    char * copyright_out, size_t copyrightMaxLength)
{
	const char * vendor = "NVIDIA";
	const char * name = "NV_OPOF";
	const char * version = NV_OPOF_VERSION;
	const char * copyright = "2024";

	if (strlen(vendor)    >= vendorMaxLength ||
		strlen(name)      >= nameMaxLength ||
		strlen(version)   >= versionMaxLength ||
		strlen(copyright) >= copyrightMaxLength)
	{
		return -1;
	}

	strcpy(vendor_out,    vendor);
	strcpy(name_out,      name);
	strcpy(version_out,   version);
	strcpy(copyright_out, copyright);
	return 0;
}

int opof_reset_server()
{
	log_info("Resetting all session/vlan/nexthop state...");
	opof_del_all_session_server();
	opof_clear_vlan_flows_server();
	opof_clear_next_hops_server();
	return 0;
}
