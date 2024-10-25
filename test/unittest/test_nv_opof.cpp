/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <algorithm>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <utility>
#include <stdio.h>
#include <stdlib.h>
#include <rte_ethdev.h>

#include "nv_opof.h"

#include "rte_flow_mock.h"

static bool is_eal_initialized = false;

static const uint32_t HT_SIZE = 1024*16; // allow UT to run w/o hugepages

static struct rte_hash_parameters params = {
	.name = "session_ht",
	.entries = HT_SIZE,
	.key_len = sizeof(struct session_key),
	.hash_func_init_val = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
};

struct rte_hash_parameters opof_vlan_flow_hash_params = {
	.name = "vlan_flow_ht",
	.entries = HT_SIZE,
	.key_len = sizeof(uint16_t),
	.hash_func_init_val = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
};

struct rte_hash_parameters opof_nexthop_hash_params = {
	.name = "nexthop_ht",
	.entries = HT_SIZE,
	.key_len = sizeof(uint32_t),
	.hash_func_init_val = 0,
	.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
};

std::string mac_to_str(const void *mac_addr)
{
    char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, (const struct rte_ether_addr*)mac_addr);
    return mac_str;
}

class OpofTest : public ::testing::Test
{
public :
	OpofTest() = default;
    ~OpofTest() override = default;

protected:
    static void SetUpTestSuite();

	void SetUp() override;
	void TearDown() override;

    void enableFlowValidation(
        const sessionRequest_t &parameters);
    
    void validateFlow(
        sessionRequest_t tc, // by copy
        uint16_t port_id,
        const struct rte_flow_attr *attr,
        const struct rte_flow_item pattern[],
        const struct rte_flow_action actions[]);

    void validateSessionFlow(
        sessionRequest_t tc,
        uint16_t port_id,
        const struct rte_flow_attr *attr,
        const struct rte_flow_item pattern[],
        const struct rte_flow_action actions[]);

    void validateNextHopFlow(
        sessionRequest_t tc,
        uint16_t port_id,
        const struct rte_flow_attr *attr,
        const struct rte_flow_item pattern[],
        const struct rte_flow_action actions[]);

    void runTestCase(
        sessionRequest_t parameters,
        nextHopParameters_t inLifNextHop = {},
        nextHopParameters_t outLifNextHop = {});
    
    static struct macRewrite_t dummyMac1, dummyMac2;

    std::map<uint32_t, nextHopParameters_t> nextHopParams;
    std::set<uint32_t> nextHopIDsToValidate;
};

struct macRewrite_t OpofTest::dummyMac1 = {
    { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
    { 0x21, 0x21, 0x21, 0x21, 0x21, 0x21 }
};
struct macRewrite_t OpofTest::dummyMac2 = {
    { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
};

void OpofTest::SetUpTestSuite()
{
    if (is_eal_initialized)
        return;

    const char *argv[] = { __FILE__, "-a00:00.0", "--no-huge", "-c0x1" };
    int argc = sizeof(argv) / sizeof(argv[0]);
    ASSERT_EQ(rte_eal_init(argc, (char**)argv), argc - 1);
    is_eal_initialized = true;
}

static uint32_t next_pow2(uint32_t x)
{
	return x == 1 ? 1 : 1 << (64 - __builtin_clzl(x - 1));
}

void OpofTest::SetUp()
{
    portid_pf[0]       = 0;
    portid_pf_vf[0][0] = 1;
    portid_pf[1]       = 2;
    portid_pf_vf[1][0] = 3;

    portid_pf_vf[0][1] = 4; // unused array slot
    portid_pf_vf[1][1] = 5; // unused array slot

	INITIATOR_PORT_ID = portid_pf[0];
	RESPONDER_PORT_ID = portid_pf[1];

	pthread_mutex_init(&off_config_g.ht_lock, NULL);
	off_config_g.session_ht = rte_hash_create(&params);
	off_config_g.session_fifo = rte_ring_create("sess_fifo", next_pow2(HT_SIZE), 0, 0);
	off_config_g.vlan_flow_ht = rte_hash_create(&opof_vlan_flow_hash_params);
    off_config_g.nexthop_ht = rte_hash_create(&opof_nexthop_hash_params);
    off_config_g.num_pfs = 2;
    off_config_g.num_reps_per_pf = 1;

	for (int pf=0; pf<off_config_g.num_reps_per_pf; pf++) {
		struct pf_port_info *port_info = &off_config_g.pf_ports[pf];
		port_info->is_enabled = portid_pf[pf] != PORT_ID_INVALID;

		port_info->pf_num = pf;
		port_info->phy_port = portid_pf[pf];
		port_info->peer_port = portid_pf[pf ^ 1];
		port_info->vf_port = portid_pf_vf[pf][0];
		port_info->vf_alt_port = PORT_ID_INVALID;
	}
}

void OpofTest::TearDown()
{
    EXPECT_EQ(ut_rte_flow_teardown(), 0);
    
    pthread_mutex_destroy(&off_config_g.ht_lock);
    
    rte_hash_free(off_config_g.session_ht);
    off_config_g.session_ht = NULL;
    
    rte_ring_free(off_config_g.session_fifo);
    off_config_g.session_fifo = NULL;

	rte_hash_free(off_config_g.vlan_flow_ht);
    off_config_g.vlan_flow_ht = NULL;

    rte_hash_free(off_config_g.nexthop_ht);
    off_config_g.nexthop_ht = NULL;
}

void OpofTest::enableFlowValidation(const sessionRequest_t &parameters)
{
    ut_rte_flow_set_flow_create_cb([&parameters, this] (
        uint16_t port_id,
        const struct rte_flow_attr *attr,
        const struct rte_flow_item pattern[],
        const struct rte_flow_action actions[])
    {
        this->validateFlow(parameters, port_id, attr, pattern, actions);
    });
}

void OpofTest::validateFlow(
    sessionRequest_t tc, // by copy
    uint16_t port_id,
    const struct rte_flow_attr *attr,
    const struct rte_flow_item pattern[],
    const struct rte_flow_action actions[])
{
    switch (attr->group) {
    case OPOF_NIC_DOMAIN_GROUP:
    case NIC_RX_GROUP:
        break; // no need to test these
    case OPOF_FDB_NEXTHOP_GROUP:
        validateNextHopFlow(tc, port_id, attr, pattern, actions);
        break;
    case OPOF_FDB_DEFAULT_GROUP:
        validateSessionFlow(tc, port_id, attr, pattern, actions);
        break;
    default:
        ADD_FAILURE() << "UNEXPECTED FLOW GROUP: " << attr->group;
    }
}

void OpofTest::validateSessionFlow(
    sessionRequest_t tc,
    uint16_t port_id,
    const struct rte_flow_attr *attr,
    const struct rte_flow_item pattern[],
    const struct rte_flow_action actions[])
{
    EXPECT_EQ(tc.ipver, _IPV4); // TODO: support IPV6

    // For the inlif==1 case, the secondary port-id is swapped.
    // For the inlif==2 case, the primary port-id is swapped.
    // Note 'tc' is passed by copy.
    bool is_reverse_path = (port_id != 0) ^ (tc.inlif != 1);
    if (is_reverse_path) {
        // Reverse the src and dst fields.
        std::swap<uint32_t>(tc.srcIP.s_addr, tc.dstIP.s_addr);
        std::swap<uint16_t>(tc.srcPort, tc.dstPort);

        if (tc.actionParams.actionParams_outLif.snatEnable) {
            // For the reverse path w/ SNAT enabled, the dst match fields must match the SNAT IP and port.
            tc.dstIP.s_addr = tc.actionParams.actionParams_outLif.snat.ipv4.s_addr;
            tc.dstPort      = tc.actionParams.actionParams_outLif.snat.port;
        }
        if (tc.actionParams.actionParams_outLif.dnatEnable) {
            // For the reverse path w/ DNAT enabled, the src match fields must match the DNAT IP and port.
            tc.srcIP.s_addr = tc.actionParams.actionParams_outLif.dnat.ipv4.s_addr;
            tc.srcPort      = tc.actionParams.actionParams_outLif.dnat.port;
        }
    }

    int field_matched_eth = 0;
    int field_matched_vlan = 0;
    int field_matched_ipv4 = 0;
    int field_matched_proto = 0;
    int field_matched_tunnel = 0;

    int action_type_matched = 0;
    int action_set_meta_matched = 0;
    int action_ttl_matched = 0;

    int expected_priority = (tc.actionParams.actionType==_FORWARD) ? FDB_FWD_PRIORITY : FDB_DROP_PRIORITY;
    EXPECT_EQ(attr->priority, expected_priority);

    for (int i=0; pattern[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
        const auto & item = pattern[i];
        switch (item.type) {
        case RTE_FLOW_ITEM_TYPE_ETH:
            ++field_matched_eth;
            break;
        case RTE_FLOW_ITEM_TYPE_IPV4: {
            if (tc.encapType != _NONE && field_matched_tunnel == 0) {
                EXPECT_EQ(item.spec, (void*)NULL);
            } else {
                EXPECT_NE(item.spec, (void*)NULL);
            }
            const auto * spec = (const struct rte_flow_item_ipv4 *)item.spec;
            if (spec) {
                // converting to native endian for easier troubleshooting
                EXPECT_EQ(htonl(spec->hdr.src_addr), tc.srcIP.s_addr) << "port_id = " << port_id << ", is_reverse_path = " << is_reverse_path;
                EXPECT_EQ(htonl(spec->hdr.dst_addr), tc.dstIP.s_addr) << "port_id = " << port_id << ", is_reverse_path = " << is_reverse_path;
                uint8_t expected_proto = tc.proto == _UDP ? IPPROTO_UDP : IPPROTO_TCP;
                EXPECT_EQ(spec->hdr.next_proto_id, expected_proto);
            }
            ++field_matched_ipv4;
            break;
        }
        case RTE_FLOW_ITEM_TYPE_VLAN: {
            const auto * spec = (const struct rte_flow_item_vlan *)item.spec;
            auto expected_vlan_tci = is_reverse_path ? tc.vlan_outLif : tc.vlan_inLif;
            EXPECT_EQ(htons(spec->tci), expected_vlan_tci);
            ++field_matched_vlan;
            break;
        }
        case RTE_FLOW_ITEM_TYPE_UDP: {
            if (tc.encapType != _NONE && field_matched_tunnel == 0) {
                // ignore outer UDP header for tunnel case
                EXPECT_EQ(item.spec, (void*)NULL);
            } else {
                EXPECT_NE(item.spec, (void*)NULL);
                EXPECT_EQ(tc.proto, _UDP);
                if (tc.proto == _UDP && item.spec) {
                    ++field_matched_proto;
                    const auto * spec = (const struct rte_flow_item_udp *)item.spec;
                    EXPECT_EQ(htons(spec->hdr.src_port), tc.srcPort) << "port_id = " << port_id << ", is_reverse_path = " << is_reverse_path;
                    EXPECT_EQ(htons(spec->hdr.dst_port), tc.dstPort) << "port_id = " << port_id << ", is_reverse_path = " << is_reverse_path;
                }
            }
            break;
        }
        case RTE_FLOW_ITEM_TYPE_TCP: {
            if (tc.encapType != _NONE && field_matched_tunnel == 0) {
                GTEST_FAIL() << "For tunnel flows, outer type cannot be TCP";
            } else {
                EXPECT_NE(item.spec, (void*)NULL);
                EXPECT_EQ(tc.proto, _TCP);
                if (tc.proto == _TCP && item.spec) {
                    ++field_matched_proto;
                    const auto * spec = (const struct rte_flow_item_tcp *)item.spec;
                    EXPECT_EQ(htons(spec->hdr.src_port), tc.srcPort) << "port_id = " << port_id << ", is_reverse_path = " << is_reverse_path;
                    EXPECT_EQ(htons(spec->hdr.dst_port), tc.dstPort) << "port_id = " << port_id << ", is_reverse_path = " << is_reverse_path;
                }
            }
            break;
        }
        case RTE_FLOW_ITEM_TYPE_GTPU:
            EXPECT_EQ(tc.encapType, _GTPU);
            ++field_matched_tunnel;
            break;
        default:
            break;
        }
    }

    for (int i=0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
        const auto & action = actions[i];
        switch (action.type) {
        case RTE_FLOW_ACTION_TYPE_QUEUE:
        case RTE_FLOW_ACTION_TYPE_JUMP:
            if (tc.actionParams.actionType == _FORWARD) {
                ++action_type_matched;
            }
            break;
        case RTE_FLOW_ACTION_TYPE_DROP:
            if (tc.actionParams.actionType == _DROP) {
                ++action_type_matched;
            }
            break;
        case RTE_FLOW_ACTION_TYPE_DEC_TTL:
            ++action_ttl_matched;
            break;
        case RTE_FLOW_ACTION_TYPE_SET_META:
        {
            const auto *set_meta = (const struct rte_flow_action_set_meta*)action.conf;
            uint32_t linkIF = is_reverse_path ? tc.inlif : tc.outlif;
            uint32_t expected_out_lif_bits = (linkIF == 1) ? MARK_PORT_0 : MARK_PORT_1;
            EXPECT_EQ(expected_out_lif_bits, set_meta->data & MARK_MASK_PORT_IDS);

            // Note DIR_IN indicates traffic arriving on inLif and leaving on outLif,
            // while DIR_OUT is the reverse.
            // This means DIR_IN associates with out_lif_next_hop, and vice versa.
            uint32_t expected_next_hop_id_bits = is_reverse_path ? 
                tc.actionParams.actionParams_inLif.nextHopId : 
                tc.actionParams.actionParams_outLif.nextHopId;
            EXPECT_EQ(expected_next_hop_id_bits, set_meta->data & MARK_MASK_NEXT_HOP);

            EXPECT_EQ(UINT32_MAX, set_meta->mask);

            ++action_set_meta_matched;
            break;
        }
        default:
            break;
        }
    }

    EXPECT_EQ(field_matched_eth, 1);
    EXPECT_EQ(field_matched_proto, 1);
    EXPECT_EQ(action_type_matched, 1);

    int expected_ipv4_match = tc.encapType == _GTPU ? 2 : 1;
    EXPECT_EQ(field_matched_ipv4, expected_ipv4_match);

    int expected_vlan_match = (tc.vlan_inLif || tc.vlan_outLif) ? 1 : 0;
    EXPECT_EQ(field_matched_vlan, expected_vlan_match);

    int expected_set_meta_match = tc.actionParams.actionType == _DROP ? 0 : 1;
    EXPECT_EQ(action_set_meta_matched, expected_set_meta_match);
}


void OpofTest::validateNextHopFlow(
    sessionRequest_t tc,
    uint16_t port_id,
    const struct rte_flow_attr *attr,
    const struct rte_flow_item pattern[],
    const struct rte_flow_action actions[])
{
    EXPECT_EQ(tc.ipver, _IPV4); // TODO: support IPV6

    uint32_t nexthop_id = 0;
    for (const auto *iter = pattern; iter->type != RTE_FLOW_ITEM_TYPE_END; ++iter) {
        if (iter->type == RTE_FLOW_ITEM_TYPE_META) {
            const auto *spec = (const rte_flow_item_meta*)iter->spec;
            nexthop_id = spec->data & MARK_MASK_NEXT_HOP;
        }
    }
    EXPECT_NE(nexthop_id, 0) << "Failed to identify nexthop ID for nexthop flow";
    if (nexthop_id == 0) {
        return;
    }
    if (this->nextHopParams.count(nexthop_id) == 0) {
        ADD_FAILURE() << "Invalid nexthop ID: " << nexthop_id;
        return;
    }

    const auto &nexthop_params = this->nextHopParams[nexthop_id];

    int field_matched_eth = 0;
    int field_matched_meta = 0;

    int action_type_matched = 0;
    int action_mac_matched = 0;
    int action_vlan_matched = 0;
    int action_nat_ip_matched = 0;
    int action_nat_port_matched = 0;
    int action_ttl_matched = 0;

    int expected_priority = 0;
    EXPECT_EQ(attr->priority, expected_priority);

    for (int i=0; pattern[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
        const auto & item = pattern[i];
        switch (item.type) {
        case RTE_FLOW_ITEM_TYPE_ETH:
            ++field_matched_eth;
            break;
        case RTE_FLOW_ITEM_TYPE_META: {
            ++field_matched_meta; // nexthop ID validated above
            break;
        }
        default:
            break;
        }
    }

    for (int i=0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
        const auto & action = actions[i];
        switch (action.type) {
        case RTE_FLOW_ACTION_TYPE_QUEUE:
        case RTE_FLOW_ACTION_TYPE_JUMP:
            ++action_type_matched;
            break;
        case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
        case RTE_FLOW_ACTION_TYPE_SET_MAC_DST:
        {
            const auto *set_mac = (const struct rte_flow_action_set_mac*)action.conf;
            const uint8_t *expected_mac = action.type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC ? 
                nexthop_params.macRewrite.srcMac : 
                nexthop_params.macRewrite.dstMac;
            EXPECT_EQ(memcmp(set_mac, expected_mac, 6), 0) 
                << "set-mac: " << mac_to_str(set_mac) << ", expected-mac: " << mac_to_str(expected_mac);
            ++action_mac_matched;
            break;
        }
        case RTE_FLOW_ACTION_TYPE_DEC_TTL:
            ++action_ttl_matched;
            break;
        case RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID:
        {
            #if 0 // TODO: nexthop
            const auto *set_vid = (const struct rte_flow_action_of_set_vlan_vid*)action.conf;
            EXPECT_EQ(set_vid->vlan_vid, htons(nexthop_params.vlan));
            #endif
            ++action_vlan_matched;
            break;
        }
        case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
        case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST:
        {
            #if 0 // TODO: nexthop: 
            const auto &nat = (action.type==RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC) 
                ? nexthop_params.snat 
                : nexthop_params.dnat;

            const auto *set_ip = (const struct rte_flow_action_set_ipv4*)action.conf;
            EXPECT_EQ(nat.ipver, _IPV4);
            EXPECT_EQ(nat.ipv4.s_addr, htonl(set_ip->ipv4_addr));
            #endif
            ++action_nat_ip_matched;
            break;
        }
        case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
        case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST:
        {
            #if 0 // TODO: nexthop: 
            const auto &nat = (action.type==RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC) 
                ? nexthop_params.snat 
                : nexthop_params.dnat;
            
            const auto *set_ip = (const struct rte_flow_action_set_ipv6*)action.conf;
            EXPECT_EQ(nat.ipver, _IPV6);
            EXPECT_EQ(set_ip->ipv6_addr, nat.ipv6.s6_addr);
            #endif
            ++action_nat_ip_matched;
            break;
        }
        case RTE_FLOW_ACTION_TYPE_SET_TCP_TP_SRC:
        case RTE_FLOW_ACTION_TYPE_SET_TCP_TP_DST:
        case RTE_FLOW_ACTION_TYPE_SET_UDP_TP_SRC:
        case RTE_FLOW_ACTION_TYPE_SET_UDP_TP_DST:
        {
            #if 0 // TODO: nexthop:
            const auto &nat = (
                action.type==RTE_FLOW_ACTION_TYPE_SET_TCP_TP_SRC ||
                action.type==RTE_FLOW_ACTION_TYPE_SET_UDP_TP_SRC) 
                ? nexthop_params.snat 
                : nexthop_params.dnat;
            uint16_t expected_proto = (
                action.type==RTE_FLOW_ACTION_TYPE_SET_TCP_TP_SRC ||
                action.type==RTE_FLOW_ACTION_TYPE_SET_TCP_TP_DST)
                ? _TCP : _UDP;
            EXPECT_EQ(nat.proto, expected_proto);

            const auto *set_port = (const struct rte_flow_action_set_tp*)action.conf;
            EXPECT_EQ(nat.port, htons(set_port->port));
            #endif
            ++action_nat_port_matched;
            break;
        }
        default:
            break;
        }
    }

    EXPECT_EQ(field_matched_eth, 1);
    EXPECT_EQ(field_matched_meta, 1);

    int expected_num_mac_write_actions = nexthop_params.macRewriteEnable ? 2 : 0;
    EXPECT_EQ(action_mac_matched, expected_num_mac_write_actions);

    int expected_num_ttl = nexthop_params.macRewriteEnable ? 1 : 0;
    EXPECT_EQ(action_ttl_matched, expected_num_ttl);

#if 0 // TODO: nexthop
    int expected_num_nat_actions = (int)nexthop_params.snatEnable + (int)nexthop_params.dnatEnable;
    EXPECT_EQ(action_nat_ip_matched, expected_num_nat_actions);
    EXPECT_EQ(action_nat_port_matched, expected_num_nat_actions);

    int expected_num_vlan_actions = (nexthop_params.vlan) ? 1 : 0;
    EXPECT_EQ(action_vlan_matched, expected_num_vlan_actions);
#endif
    this->nextHopIDsToValidate.erase(nexthop_id);
}

void OpofTest::runTestCase(
        sessionRequest_t parameters,
        nextHopParameters_t inLifNextHop,
        nextHopParameters_t outLifNextHop)
{
    bool has_nexthop = inLifNextHop.nextHopId || outLifNextHop.nextHopId;
    ut_rte_flow_expect_create_calls(has_nexthop ? 4 : 2);

    // Enable the rte_flow mock to inspect all flows created by the OPOF under test
    enableFlowValidation(parameters);

    if (has_nexthop) {
        // Ensure sessions are rejected if they reference a non-existant nexthop
        addSessionResponse_t responseAdd = {};
        EXPECT_NE(opof_add_session_server(&parameters, &responseAdd), _OK);

        if (inLifNextHop.nextHopId) {
            this->nextHopIDsToValidate.insert(inLifNextHop.nextHopId);
            this->nextHopParams[inLifNextHop.nextHopId] = inLifNextHop;
            opof_set_next_hop_server(&inLifNextHop);
        }
        if (outLifNextHop.nextHopId) {
            this->nextHopIDsToValidate.insert(outLifNextHop.nextHopId);        
            this->nextHopParams[outLifNextHop.nextHopId] = outLifNextHop;        
            opof_set_next_hop_server(&outLifNextHop);
        }
    }

    addSessionResponse_t responseAdd = {};
    EXPECT_EQ(opof_add_session_server(&parameters, &responseAdd), _OK);
    EXPECT_EQ(responseAdd.requestStatus, _ACCEPTED);

    sessionResponse_t responseDel = {};
    EXPECT_EQ(opof_del_session_server(responseAdd.sessionErrors->sessionId, &responseDel), _OK);

    EXPECT_EQ(this->nextHopIDsToValidate.size(), 0) << "Not all nextHop IDs resulted in flows";
}

TEST_F(OpofTest, TestBasicUdpFlow)
{
    runTestCase({
        .inlif = 1,
        .outlif = 2,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { .actionType = _FORWARD, },
    });
}

TEST_F(OpofTest, TestBasicTcpFlow)
{
    runTestCase({
        .inlif = 1,
        .outlif = 2,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _TCP,
        .ipver = _IPV4,
        .actionParams = { .actionType = _FORWARD, },
    });
}

TEST_F(OpofTest, TestDropFlow)
{
    runTestCase({
        .inlif = 1,
        .outlif = 2,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { .actionType = _DROP, },
    });
}

TEST_F(OpofTest, TestReverseFlow)
{
    runTestCase({
        .inlif = 2,
        .outlif = 1,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { .actionType = _FORWARD, },
    });
}

TEST_F(OpofTest, TestNextHopMac)
{
    runTestCase({
        .inlif = 2,
        .outlif = 1,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { 
            .actionType = _FORWARD, 
            .actionParams_inLif = { .nextHopId = 111 },
            .actionParams_outLif = { .nextHopId = 222 },
        },
    },
    {
        .nextHopId = 111,
        .macRewriteEnable = true,
        .macRewrite = dummyMac1,
    },
    {
        .nextHopId = 222,
        .macRewriteEnable = true,
        .macRewrite = dummyMac2,
    });
}

TEST_F(OpofTest, TestNAT)
{
    runTestCase({
        // note inlif/outlif are reversed
        .inlif = 2,
        .outlif = 1,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { 
            .actionType = _FORWARD, 
            .actionParams_inLif = {
                .snatEnable = true,
                .snat = { 
                    .ipver = _IPV4,
                    .ipv4 = { .s_addr = 12345 }, 
                    .proto = _UDP,
                    .port = 88 
                },
                .dnatEnable = true,
                .dnat = { 
                    .ipver = _IPV4,
                    .ipv4 = { .s_addr = 5678 }, 
                    .proto = _UDP,
                    .port = 99 
                },
            },
            .actionParams_outLif = {
                .snatEnable = true,
                .snat = { 
                    .ipver = _IPV4,
                    .ipv4 = { .s_addr = 0x57575757 }, 
                    .proto = _UDP,
                    .port = 102
                },
                .dnatEnable = true,
                .dnat = { 
                    .ipver = _IPV4,
                    .ipv4 = { .s_addr = 0x68686868 }, 
                    .proto = _UDP,
                    .port = 103
                },
            },
        },
    });
}

TEST_F(OpofTest, TestNextHopVLAN)
{
    runTestCase({
        // note inlif/outlif are reversed
        .inlif = 2,
        .outlif = 1,
        .vlan_outLif = 555,
        .vlan_inLif = 222,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { 
            .actionType = _FORWARD, 
            .actionParams_inLif = {
                .vlan = 456,
            },
            .actionParams_outLif = {
                .vlan = 123,
            },
        },
    });
}

TEST_F(OpofTest, TestNextHopTunnel)
{
    runTestCase({
        .inlif = 2,
        .outlif = 1,
        .encapType = _GTPU,
        .srcIP = { 123456 },
        .dstIP = { 567890 },
        .srcPort = 55,
        .dstPort = 66,
        .proto = _UDP,
        .ipver = _IPV4,
        .actionParams = { 
            .actionType = _FORWARD, 
        },
    });
}

class OpofVlanTest : public ::testing::Test
{
public :
	OpofVlanTest() = default;
    ~OpofVlanTest() override = default;

protected:
    struct TestCase {
        uint16_t vlan_id;
        uint16_t vf_index;
    };
    static void SetUpTestSuite();

	void SetUp() override;
	void TearDown() override;

    void injectNFlows(size_t N);

    void enableFlowValidation(
        const TestCase &parameters);
    
    void validateFlow(
        TestCase tc, // by copy
        uint16_t port_id,
        const struct rte_flow_attr *attr,
        const struct rte_flow_item pattern[],
        const struct rte_flow_action actions[]);

    void runTestCase(
        TestCase parameters);
};


void OpofVlanTest::SetUpTestSuite()
{
    if (is_eal_initialized)
        return;

    const char *argv[] = { __FILE__, "-a00:00.0", "--no-huge", "-c0x1" };
    int argc = sizeof(argv) / sizeof(argv[0]);
    ASSERT_EQ(rte_eal_init(argc, (char**)argv), argc - 1);
    is_eal_initialized = true;
}

void OpofVlanTest::SetUp()
{
    portid_pf[0]       = 0;
    portid_pf_vf[0][0] = 1;
    portid_pf_vf[0][1] = 2;
    portid_pf[1]       = 3;
    portid_pf_vf[1][0] = 4;
    portid_pf_vf[1][1] = 5;

	INITIATOR_PORT_ID = portid_pf[0];
	RESPONDER_PORT_ID = portid_pf[1];

	pthread_mutex_init(&off_config_g.ht_lock, NULL);
	off_config_g.session_ht = rte_hash_create(&params);
	off_config_g.session_fifo = rte_ring_create("sess_fifo", next_pow2(MAX_SESSION), 0, 0);
	off_config_g.vlan_flow_ht = rte_hash_create(&opof_vlan_flow_hash_params);
    off_config_g.nexthop_ht = rte_hash_create(&opof_nexthop_hash_params);
    off_config_g.num_pfs = 2;
    off_config_g.num_reps_per_pf = 2;
	for (int pf=0; pf<off_config_g.num_reps_per_pf; pf++) {
		struct pf_port_info *port_info = &off_config_g.pf_ports[pf];
		port_info->is_enabled = portid_pf[pf] != PORT_ID_INVALID;

		port_info->pf_num = pf;
		port_info->phy_port = portid_pf[pf];
		port_info->peer_port = portid_pf[pf ^ 1];
		port_info->vf_port = portid_pf_vf[pf][0];
		port_info->vf_alt_port = portid_pf_vf[pf][1];
	}
}

void OpofVlanTest::TearDown()
{
    EXPECT_EQ(ut_rte_flow_teardown(), 0);
    
    pthread_mutex_destroy(&off_config_g.ht_lock);
    
    rte_hash_free(off_config_g.session_ht);
    off_config_g.session_ht = NULL;
    
    rte_ring_free(off_config_g.session_fifo);
    off_config_g.session_fifo = NULL;

	rte_hash_free(off_config_g.vlan_flow_ht);
    off_config_g.vlan_flow_ht = NULL;

    rte_hash_free(off_config_g.nexthop_ht);
    off_config_g.nexthop_ht = NULL;
}

void OpofVlanTest::enableFlowValidation(const TestCase &parameters)
{
    ut_rte_flow_set_flow_create_cb([&parameters, this] (
        uint16_t port_id,
        const struct rte_flow_attr *attr,
        const struct rte_flow_item pattern[],
        const struct rte_flow_action actions[])
    {
        this->validateFlow(parameters, port_id, attr, pattern, actions);
    });
}

void OpofVlanTest::validateFlow(
    TestCase tc, // by copy
    uint16_t port_id,
    const struct rte_flow_attr *attr,
    const struct rte_flow_item pattern[],
    const struct rte_flow_action actions[])
{
    EXPECT_TRUE(port_id == portid_pf[0] || port_id == portid_pf[1]) << "port_id = " << port_id;
    EXPECT_EQ(attr->priority, FDB_TAGGED_NO_MATCH_PRIORITY);

    int field_matched_eth = 0;
    int field_matched_vlan = 0;

    int action_type_matched = 0;

    for (int i=0; pattern[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
        const auto & item = pattern[i];
        switch (item.type) {
        case RTE_FLOW_ITEM_TYPE_ETH:
            ++field_matched_eth;
            break;
        case RTE_FLOW_ITEM_TYPE_VLAN: {
            const auto * spec = (const struct rte_flow_item_vlan *)item.spec;
            EXPECT_EQ(htons(spec->tci), tc.vlan_id);
            ++field_matched_vlan;
            break;
        }
        default:
            ADD_FAILURE() << "Unexpected item type: " << item.type;
            break;
        }
    }

    for (int i=0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
        const auto & action = actions[i];
        switch (action.type) {
        case RTE_FLOW_ACTION_TYPE_COUNT:
            break;
        case RTE_FLOW_ACTION_TYPE_PORT_ID: {

            uint32_t actual_dest_port =
                ((struct rte_flow_action_port_id*)action.conf)->id;

            uint32_t expected_dest_port = (port_id==portid_pf[0]) ?
                (tc.vf_index==1 ? portid_pf_vf[0][0] : portid_pf_vf[0][1]) :
                (tc.vf_index==1 ? portid_pf_vf[1][0] : portid_pf_vf[1][1]);
            
            EXPECT_EQ(actual_dest_port, expected_dest_port);
            ++action_type_matched;
            break;
        }
        default:
            ADD_FAILURE() << "Unexpected action type: " << action.type;
            break;
        }
    }

    EXPECT_EQ(field_matched_eth, 1);
    EXPECT_EQ(field_matched_vlan, 1);
    EXPECT_EQ(action_type_matched, 1);
}

void OpofVlanTest::runTestCase(
        TestCase parameters)
{
    ut_rte_flow_expect_create_calls(2);

    enableFlowValidation(parameters);

    EXPECT_EQ(opof_add_vlan_flow_server(parameters.vlan_id, parameters.vf_index), 0);
}

void OpofVlanTest::injectNFlows(size_t N)
{
    for (size_t i=0; i<N; i++) {
        TestCase tc = { (uint16_t)(100+i), (uint16_t)((i%2) + 1) };
        runTestCase(tc);
        EXPECT_EQ(opof_get_vlan_flow_count_server(), i + 1);
    }
}

TEST_F(OpofVlanTest, AddRemoveMultiple)
{
    TestCase tc1 = { 100, 1 };
    runTestCase(tc1);
    EXPECT_EQ(opof_get_vlan_flow_count_server(), 1);

    TestCase tc2 = { 101, 2 };
    runTestCase(tc2);
    EXPECT_EQ(opof_get_vlan_flow_count_server(), 2);

    // Fail to insert duplicate
    EXPECT_NE(opof_add_vlan_flow_server(tc1.vlan_id, tc1.vf_index), 0);

    EXPECT_EQ(opof_remove_vlan_flow_server(100), 0);
    EXPECT_EQ(opof_get_vlan_flow_count_server(), 1);

    EXPECT_EQ(opof_remove_vlan_flow_server(101), 0);
    EXPECT_EQ(opof_get_vlan_flow_count_server(), 0);
}

TEST_F(OpofVlanTest, Query)
{
    constexpr size_t NVLANS = 8;
    injectNFlows(NVLANS);

    std::vector<uint16_t> currentVlanIDs(NVLANS);
    std::vector<uint16_t> currentVFs(NVLANS);
    size_t currentFlows = 0;
    EXPECT_EQ(opof_get_vlan_flows_server(currentVlanIDs.data(), currentVFs.data(), NVLANS, &currentFlows), 0);
    EXPECT_EQ(currentFlows, NVLANS);

    std::vector<std::pair<uint16_t, uint16_t>> vlan_flows(NVLANS);
    for (size_t i=0; i<NVLANS; i++) {
        vlan_flows[i] = { currentVlanIDs[i], currentVFs[i] };
    }
    std::sort(std::begin(vlan_flows), std::end(vlan_flows));
    for (size_t i=0; i<NVLANS; i++) {
        // match the implementation of injectNFlows
        EXPECT_EQ(vlan_flows[i].first, 100+i);
        EXPECT_EQ(vlan_flows[i].second, ((i%2)+1));
    }
}

TEST_F(OpofVlanTest, Clear)
{
    constexpr size_t NVLANS = 12;
    injectNFlows(NVLANS);
    EXPECT_EQ(opof_get_vlan_flow_count_server(), NVLANS);
    EXPECT_EQ(opof_clear_vlan_flows_server(), 0);
    EXPECT_EQ(opof_get_vlan_flow_count_server(), 0);
    EXPECT_EQ(opof_reset_server(), 0);
}
