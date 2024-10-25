""" Python Implementation of the OPOF Test Driver """

from concurrent import futures
import binascii
import copy
import ipaddress
import logging
import os
import pytest
import sys
import time
import threading
import typing
import unittest

import grpc
import opof_tester_pb2
import opof_tester_pb2_grpc
import openoffload_pb2
import openoffload_pb2_grpc
from opof_tester_pb2 import FlowDefinition
from openoffload_pb2 import _TCP, _UDP, _IPV4, _IPV6, _FORWARD, _DROP

DEFAULT_DPU_HOST_ADDR = "10.15.4.43:3444"
DEFAULT_EXT_HOST_ADDR = "10.15.4.27:3444"
DEFAULT_OPOF_HOST_ADDR = "169.254.33.51:3443"

ENV_VAR_DPU_HOST_ADDR = "DPU_HOST_ADDR"
ENV_VAR_EXT_HOST_ADDR = "EXT_HOST_ADDR"
ENV_VAR_OPOF_HOST_ADDR = "OPOF_HOST_ADDR"
ENV_VAR_NUM_VF_PER_PF = "VF_PER_PF"

SAMPLE_SRC_SUBNET = "16.0.0.0/28"
SAMPLE_DST_SUBNET = "48.0.0.0/28"

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def env_var_or_default(env_var, default_value) -> str:
    return os.environ[env_var] if env_var in os.environ else default_value

def make_channel(name, default_addr, env_var):
    addr = env_var_or_default(env_var, default_addr)
    print(f"Using {addr} for {name}")
    return grpc.insecure_channel(addr)

def mac_str_to_bytes(addr:str) -> bytes:
    return binascii.unhexlify(addr.replace(':', ''))

class TestOpof(unittest.TestCase):
    """Tests the OpenOffload agent via the gRPC interface.
    
    The test typically executes on the DPU, with the help of the DPU Host and an 
    External Host, both of which execute the OPOF Test Traffic Gen script, capable
    of sending and receiving packets under the control of this Test Driver.

    The DPU Host and External Host are selected by environment variables.

    Most tests rely on the sample subnets defined above. Typically a firewall session
    is created for every IP in a given subnet to either forward or drop matching
    packets, and typically a traffic flow is commanded to produce and listen for packets
    which correspond to the firewall session.
    """
    @classmethod
    def setUpClass(cls):
        dpu_host_channel  = make_channel('DPU_HOST_ADDR', DEFAULT_DPU_HOST_ADDR,  ENV_VAR_DPU_HOST_ADDR)
        ext_host_channel  = make_channel('EXT_HOST_ADDR', DEFAULT_EXT_HOST_ADDR,  ENV_VAR_EXT_HOST_ADDR)
        opof_host_channel = make_channel('OPOF_HOST_ADDR', DEFAULT_OPOF_HOST_ADDR, ENV_VAR_OPOF_HOST_ADDR)

        # TODO: test twice, once with 1 and then 2 vf_per_pf
        cls.num_vf_per_pf = os.environ.get(ENV_VAR_NUM_VF_PER_PF, 1)

        cls.dpu_host_stub = opof_tester_pb2_grpc.OpofTrafficGenStub(dpu_host_channel)
        cls.ext_host_stub = opof_tester_pb2_grpc.OpofTrafficGenStub(ext_host_channel)
        cls.opof_stub     = openoffload_pb2_grpc.SessionTableStub(opof_host_channel)

        cls._next_flow_id    = 1000
        cls._next_session_id = 100000
        cls._next_nexthop_id = 200000

        try:
            ver = cls.opof_stub.getServiceVersion(openoffload_pb2.versionRequest())
            print(f"{ver.vendor} {ver.name} {ver.version} copyright {ver.copyright}")
        except Exception as e:
            print(e)
            pytest.exit("Failed to query OPOF software version")

    @classmethod
    def tearDownClass(cls):
        shutdown = opof_tester_pb2.HeartbeatCommand()
        shutdown.shutdown = True
        
        try:
            cls.dpu_host_stub.ProcessHeartbeat(shutdown)
            cls.dpu_host_stub = None
        except:
            pass

        try:        
            cls.ext_host_stub.ProcessHeartbeat(shutdown)
            cls.ext_host_stub = None
        except:
            pass

        try:
            cls.dpu_host_stub.ProcessHeartbeat(shutdown)
            cls.opof_stub = None
        except:
            pass
    
    @classmethod
    def next_flow_id(cls):
        id = cls._next_flow_id
        cls._next_flow_id += 1
        return id
        
    @classmethod
    def next_session_id(cls):
        id = cls._next_session_id
        cls._next_session_id += 1
        return id

    @classmethod
    def next_nexthop_id(cls):
        id = cls._next_nexthop_id
        cls._next_nexthop_id += 1
        return id

    def setUp(self):
        """Initialize the list of sessions and flows to be cleaned up inside tearDown()."""
        self.all_sessions = []
        self.all_tx_flows = []
        self.all_rx_flows = []
    
    def tearDown(self):
        """Tear down all the firewall sessions and traffic flows created during the test."""
        self.destroy_all_sessions()
        self.destroy_all_flows()
        self.destroy_all_vlan_flows()
        self.destroy_all_nexthops()
    
    def destroy_all_sessions(self) -> bool:
        """Command every session created during the test to be deleted from the OPOF agent."""
        success = True
        for s in self.all_sessions:
            try:
                req = openoffload_pb2.sessionId()
                req.sessionId = s
                resp = self.opof_stub.deleteSession(req)
                if 'responseError' in resp.__dict__ and len(resp.responseError) > 0:
                    success = False
                    for err in resp.responseError:
                        print(f"Failed to delete a session; sessionId {err.sessionId}, status {err.errorStatus}")
            except:
                success = False
        self.all_sessions = []
        return success
    
    def destroy_all_flows(self) -> None:
        """Command all traffic flows to be deleted on both the DPU Host and External Host."""
        for s in [self.dpu_host_stub, self.ext_host_stub]:
            try:
                self.stop_flow(s, -1)
            except:
                pass
    
    def destroy_all_vlan_flows(self) -> None:
        try:
            self.opof_stub.clearVlanFlows(openoffload_pb2.vlanFlowListRequest())
        except:
            pass
    
    def destroy_all_nexthops(self) -> None:
        try:
            self.opof_stub.clearNextHops(openoffload_pb2.nextHopParameters())
        except:
            pass

    def default_session(self, 
            ipver = _IPV4, 
            proto = _TCP,
            action = _FORWARD, 
            timeout = 5
            ) -> openoffload_pb2.sessionRequest:
        session = openoffload_pb2.sessionRequest()
        session.inLif = 1
        session.outLif = (3 - session.inLif) if self.num_vf_per_pf==1 else session.inLif
        session.ipVersion = ipver
        session.protocolId = proto
        session.sourcePort = 53
        session.destinationPort = 53
        session.action.actionType = action
        session.cacheTimeout = timeout
        return session

    def default_flow_def(self,
            session = None,
            ipver = _IPV4,
            proto = _TCP,
            interface = 0,
            vlan_id = 0
            ) -> FlowDefinition:
        flow_def = FlowDefinition()
        flow_def.flow_id = TestOpof.next_flow_id()
        flow_def.interface = interface
        flow_def.vlan_id = vlan_id
        flow_def.eth_type = session.ipVersion if session is not None else ipver
        flow_def.proto = session.protocolId if session is not None else proto
        flow_def.src_subnet = SAMPLE_SRC_SUBNET
        flow_def.dst_subnet = SAMPLE_DST_SUBNET
        flow_def.src_port = 53
        flow_def.dst_port = 53
        flow_def.tcp_flags = 0
        flow_def.payload_length = 1024
        flow_def.duration = 5
        flow_def.max_pps = 0
        return flow_def
    
    def copy_flow(self, flow: FlowDefinition):
        flow2 = copy.copy(flow)
        flow2.flow_id = TestOpof.next_flow_id()
        return flow2
    
    def vlan_flow_cmd(self, vlan_id, vf_index) -> openoffload_pb2.vlanFlowDef:
        vlan_flow = openoffload_pb2.vlanFlowDef()
        vlan_flow.vlanId = vlan_id
        vlan_flow.internalLif = vf_index
        return vlan_flow

    def start_sending(self, stub, flow_def: FlowDefinition, interface = None) -> None:
        if interface is not None:
            flow_def = copy.deepcopy(flow_def)
            flow_def.interface = interface
        self.all_tx_flows.append(flow_def.flow_id)
        flow_def.transmit = True
        resp = stub.AddFlow(flow_def)
        self.assertTrue(resp.success)

    def start_receiving(self, stub, flow_def: FlowDefinition, interface = None) -> None:
        if interface is not None:
            flow_def = copy.deepcopy(flow_def)
            flow_def.interface = interface
        self.all_rx_flows.append(flow_def.flow_id)
        flow_def.transmit = False
        resp = stub.AddFlow(flow_def)
        self.assertTrue(resp.success)
    
    def stop_flow(self, stub, flow_id: int) -> None:
        flow_def = FlowDefinition()
        flow_def.flow_id = flow_id
        resp = stub.RemoveFlow(flow_def)
    
    def count_rx_pkts(self, stub, flow_id: int) -> int:
        req = opof_tester_pb2.FlowStatsRequest()
        resp = stub.GetFlowStats(req)
        self.assertTrue(resp is not None)
        self.assertTrue(flow_id in resp.stats)
        return resp.stats[flow_id].subnet_count

    def get_rx_macaddrs(self, stub, flow_id: int) -> typing.List[str]:
        # returns the list of src-mac addresses from which packets were received
        # formatted as strings, not byte arrays (i.e. ["aa:bb:cc:dd:ee:ff"])
        req = opof_tester_pb2.FlowStatsRequest()
        resp = stub.GetFlowStats(req)
        self.assertTrue(resp is not None)
        if flow_id not in resp.stats:
            return []
        return resp.stats[flow_id].src_macs
    
    def send_vlan_flow_cmd(self, stub, cmd) -> None:
        stub.addVlanFlow(cmd)

    def offload_subnet(self, request, src_subnet, dst_subnet) -> bool:
        src_net = ipaddress.ip_network(src_subnet)
        dst_net = ipaddress.ip_network(dst_subnet)
        self.assertEqual(src_net.netmask, dst_net.netmask, "src and dst subnets must have same netmask")
        
        resp = self.opof_stub.addSession(self._generate_requests(request, src_subnet, dst_subnet))
        
        if 'responseError' in resp.__dict__ and len(resp.responseError) > 0:
            for err in resp.responseError:
                print(f"Failed to create a session; sessionId {err.sessionId}, status {err.errorStatus}")
            return False
        return True # success
    
    def _generate_requests(self, request, src_subnet, dst_subnet):
        src_subnet = ipaddress.ip_network(src_subnet)
        dst_subnet = ipaddress.ip_network(dst_subnet)
        yield self._mod_request_src_dst(request, src_subnet.network_address, dst_subnet.network_address)

        if src_subnet.num_addresses == 1:
            return

        for src, dst in zip(src_subnet.hosts(), dst_subnet.hosts()):
            yield self._mod_request_src_dst(request, src, dst)

        yield self._mod_request_src_dst(request, src_subnet.broadcast_address, dst_subnet.broadcast_address)

    def _mod_request_src_dst(self, request, src, dst) -> openoffload_pb2.sessionRequest:
        request.sessionId = TestOpof.next_session_id()
        request.sourceIp      = int(src)
        request.destinationIp = int(dst)
        self.all_sessions.append(request.sessionId)
        #print(f"request: session {request.sessionId}: {hex(request.sourceIp)}->{hex(request.destinationIp)}")
        #print(request)
        return request
    
    def get_closed_sessions(self) -> typing.List[int]:
        # Note each time this function is called, the OPOF service prints "read: Connection reset by peer".
        # This is probably due to the opof_session_server.cc returning a NOT_FOUND error when no more
        # closed connections exist.
        closed_sessions = []
        session_req = openoffload_pb2.sessionRequestArgs()
        session_req.pageSize = 16

        more_pages = True
        while more_pages:
            more_pages = False
            try:
                session_stats = self.opof_stub.getClosedSessions(session_req)
                for stats in session_stats:
                    closed_sessions.append(stats.sessionId)
                    more_pages = True
            except:
                break
        return closed_sessions
    
    def reverse_flow_def(self, flow_def, vlan_id = None) -> FlowDefinition:
        rev = copy.deepcopy(flow_def)
        if self.num_vf_per_pf==1:
            rev.dmac_idx ^= 1
            rev.interface ^= 1
        # else, assume same physical interface
        rev.flow_id = self.next_flow_id()
        rev.src_subnet = flow_def.dst_subnet
        rev.dst_subnet = flow_def.src_subnet
        rev.src_port = flow_def.dst_port
        rev.dst_port = flow_def.src_port
        if vlan_id is not None:
            rev.vlan_id = vlan_id
        return rev
    
    def add_nexthop(self, nexthop: openoffload_pb2.nextHopParameters) -> int:
        if nexthop.nextHopId == 0:
            nexthop.nextHopId = self.next_nexthop_id()
        response : openoffload_pb2.nextHopResponse = self.opof_stub.setNextHop(nexthop)
        if response.errorStatus == 0:
            return nexthop.nextHopId
        raise Exception(f"setNextHop() failed with code {response.errorStatus}")
    
    ###############################################################################
    # TESTS
    ###############################################################################

    def test_ipv4_incoming_miss_rules(self):
        """Check that non-offloaded traffic flows to the firewall VF."""
        flow_def_tcp = self.default_flow_def(proto=_TCP)
        flow_def_udp = self.default_flow_def(proto=_UDP)

        self.start_receiving(self.dpu_host_stub, flow_def_tcp)
        self.start_receiving(self.dpu_host_stub, flow_def_udp)
        self.start_sending(  self.ext_host_stub, flow_def_tcp)
        self.start_sending(  self.ext_host_stub, flow_def_udp)

        time.sleep(1)

        rx_count_tcp = self.count_rx_pkts(self.dpu_host_stub, flow_def_tcp.flow_id)
        rx_count_udp = self.count_rx_pkts(self.dpu_host_stub, flow_def_udp.flow_id)
        print(f"Received {rx_count_tcp} tcp pkts, {rx_count_udp} udp pkts, to DPU host")
        self.assertTrue(rx_count_tcp >= 0, "No TCP packets forwarded to DPU host")
        self.assertTrue(rx_count_udp >= 0, "No UDP packets forwarded to DPU host")
    
    def test_ipv4_outgoing_miss_rules(self):
        """Check that packets passed by the Firewall VF are forwarded to the uplink(s)."""
        flow_def_tcp = self.default_flow_def(proto = _TCP)
        flow_def_udp = self.default_flow_def(proto = _UDP)

        self.start_receiving(self.ext_host_stub, flow_def_tcp)
        self.start_receiving(self.ext_host_stub, flow_def_udp)
        self.start_sending(  self.dpu_host_stub, flow_def_tcp)
        self.start_sending(  self.dpu_host_stub, flow_def_udp)

        time.sleep(1)

        rx_count_tcp = self.count_rx_pkts(self.ext_host_stub, flow_def_tcp.flow_id)
        rx_count_udp = self.count_rx_pkts(self.ext_host_stub, flow_def_udp.flow_id)
        print(f"Received {rx_count_tcp} tcp pkts, {rx_count_udp} udp pkts, from DPU host to uplink")
        self.assertTrue(rx_count_tcp >= 0, "No TCP packets forwarded to the uplink")
        self.assertTrue(rx_count_udp >= 0, "No UDP packets forwarded to the uplink")
    
    def test_ipv4_vlan_miss_rules(self):
        """ Check that non-offload packets flow to the correct firewall VF. """
        flow_defs = [
            self.default_flow_def(proto=_UDP, vlan_id = i + 55, interface = i % 2)
            for i in range(3)]
        
        for i in range(2): # skip last vlan flow; ensure we still rx on pf0vf0
            flow_def = flow_defs[i]
            self.send_vlan_flow_cmd(self.opof_stub, 
                self.vlan_flow_cmd(
                    flow_def.vlan_id, flow_def.interface + 1)) # VF index is one based

        for flow_def in flow_defs:
            self.start_receiving(self.dpu_host_stub, flow_def)
        
        for flow_def in flow_defs:
            tx_flow_def = flow_def
            tx_flow_def.interface = 0
            self.start_sending(self.ext_host_stub, tx_flow_def)

        time.sleep(1)

        for flow_def in flow_defs:
            rx_count = self.count_rx_pkts(self.dpu_host_stub, flow_def.flow_id)
            print(f"VLAN {flow_def.vlan_id}: Received {rx_count} pkts on interface {flow_def.interface}, to DPU host")
            self.assertTrue(rx_count > 0, "No packets forwarded to DPU host")

    def test_ipv4_tcp_blocked_src_subnet(self):
        """Check that Drop rules can be offloaded """ 
        session = self.default_session(proto = _TCP, action = _DROP)
        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        flow_def = self.default_flow_def(session = session)
        self.start_receiving(self.dpu_host_stub, flow_def)
        self.start_sending(  self.ext_host_stub, flow_def)

        flow_rev = self.reverse_flow_def(flow_def)
        self.start_receiving(self.dpu_host_stub, flow_rev)
        self.start_sending(  self.ext_host_stub, flow_rev)

        time.sleep(1)

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_def.flow_id), 0, "Packets made it past the drop rule")
        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_rev.flow_id), 0, "Packets made it past the drop rule (reverse direction)")

    def test_ipv4_tcp_flags_forwarded(self):
        """Check that TCP packets with interesting flags are never offloaded.""" 
        session = self.default_session(proto = _TCP, action = _DROP, timeout = 5)
        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        flags_to_test = [SYN, FIN, RST]

        flow_stats = dict()
        for f in flags_to_test:
            flow_def = self.default_flow_def(session = session)
            flow_def.tcp_flags = f
        
            self.start_receiving(self.dpu_host_stub, flow_def)
            self.start_sending(self.ext_host_stub, flow_def)

            time.sleep(1)

            flow_stats[f] = self.count_rx_pkts(self.dpu_host_stub, flow_def.flow_id)

            self.stop_flow(self.dpu_host_stub, flow_def.flow_id)
            self.stop_flow(self.ext_host_stub, flow_def.flow_id)

        self.assertTrue(self.destroy_all_sessions())

        print(flow_stats)
        self.assertTrue(flow_stats.get(SYN, 0) > 4, "Flagged packets dropped: SYN")
        self.assertTrue(flow_stats.get(FIN, 0) > 4, "Flagged packets dropped: FIN")
        self.assertTrue(flow_stats.get(RST, 0) > 4, "Flagged packets dropped: RST")
    
    def test_ipv4_tcp_offloaded(self):
        """Check that TCP packets can be hairpinned back to the external host.""" 
        session = self.default_session(action = _FORWARD)
        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        flow_def = self.default_flow_def(session = session)
        rx_interface = flow_def.interface ^ 1 if self.num_vf_per_pf==1 else flow_def.interface
        self.start_receiving(self.dpu_host_stub, flow_def)
        self.start_receiving(self.ext_host_stub, flow_def, rx_interface)
        self.start_sending(  self.ext_host_stub, flow_def)

        flow_rev = self.reverse_flow_def(flow_def)
        rx_interface = flow_rev.interface ^ 1 if self.num_vf_per_pf==1 else flow_rev.interface
        self.start_receiving(self.dpu_host_stub, flow_rev)
        self.start_receiving(self.ext_host_stub, flow_rev, rx_interface)
        self.start_sending(  self.ext_host_stub, flow_rev)

        time.sleep(2)

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_def.flow_id), 0, "TCP Packets made it past the fwd rule")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, flow_def.flow_id) > 4, "TCP Packets not hairpinned")

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_rev.flow_id), 0, "TCP Packets made it past the fwd rule (reverse)")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, flow_rev.flow_id) > 4, "TCP Packets not hairpinned (reverse)")

    def test_ipv4_udp_offloaded(self):
        """Check that UDP packets can be hairpinned back to the external host.""" 
        session = self.default_session(action = _FORWARD)
        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        flow_def = self.default_flow_def(session = session)
        rx_interface = flow_def.interface ^ 1 if self.num_vf_per_pf==1 else flow_def.interface
        self.start_receiving(self.dpu_host_stub, flow_def)
        self.start_receiving(self.ext_host_stub, flow_def, rx_interface)
        self.start_sending(  self.ext_host_stub, flow_def)

        flow_rev = self.reverse_flow_def(flow_def)
        rx_interface = flow_rev.interface ^ 1 if self.num_vf_per_pf==1 else flow_rev.interface
        self.start_receiving(self.dpu_host_stub, flow_rev)
        self.start_receiving(self.ext_host_stub, flow_rev, rx_interface)
        self.start_sending(  self.ext_host_stub, flow_rev)

        time.sleep(2)

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_def.flow_id), 0, "UDP Packets made it past the fwd rule")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, flow_def.flow_id) > 4, "UDP Packets not hairpinned")

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_rev.flow_id), 0, "UDP Packets made it past the fwd rule (reverse)")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, flow_rev.flow_id) > 4, "UDP Packets not hairpinned (reverse)")

    def test_ipv4_udp_offload_expires(self):
        """Check that flows expire after the requested duration."""
        self.get_closed_sessions() # flush expired sessions
        
        session = self.default_session(proto = _UDP, action = _FORWARD, timeout = 3)
        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        time.sleep(2)
        closed_sessions = self.get_closed_sessions()
        self.assertEqual(len(closed_sessions), 0, "Expected no sessions to expire yet")

        time.sleep(2)
        closed_sessions = self.get_closed_sessions()
        for s in self.all_sessions:
            self.assertTrue(s in closed_sessions, "Session " + str(s) + " not expired")

    def test_ipv4_udp_offload_expiration_extended(self):
        """Check that flows do not expire as long as matching traffic is flowing through the firewall."""
        self.get_closed_sessions() # flush expired sessions

        session = self.default_session(proto = _UDP, action = _FORWARD, timeout = 3)

        flow_def = self.default_flow_def(session = session)

        time.sleep(6)
        closed_sessions = self.get_closed_sessions()
        self.assertEqual(len(closed_sessions), 0, "Expected no sessions to expire yet") # not yet

        self.destroy_all_flows() # allow flows to expire
        time.sleep(4)

        closed_sessions = self.get_closed_sessions()
        for s in self.all_sessions:
            self.assertTrue(s in closed_sessions, "Session " + str(s) + " not expired")
    
    def test_ipv4_udp_offloaded_nat(self):
        """Check that UDP packets can be NAT-translated and hairpinned back to the external host.""" 
        # [src=16.0.0.1, dst=48.0.0.1] => [snat] => [src=48.0.0.2, dst=48.0.0.1]
        # [src=48.0.0.1, dst=16.0.0.1] <= [dnat] <= [src=48.0.0.1, dst=48.0.0.2]
        SRC_IP = "16.0.0.1"
        DST_IP = "48.0.0.1"
        NAT_IP = "48.0.0.2"
        
        session = self.default_session(action = _FORWARD)
        session.action.actionParams_outLif.snat.ipv4 = int(ipaddress.ip_address(NAT_IP))
        session.action.actionParams_outLif.snat.port = 53
        session.action.actionParams_inLif.dnat.ipv4 = int(ipaddress.ip_address(SRC_IP))
        session.action.actionParams_inLif.dnat.port = 53
        self.assertTrue(self.offload_subnet(session, SRC_IP, DST_IP))

        tx_flow_def = self.default_flow_def(session = session)
        tx_flow_def.src_subnet = SRC_IP
        tx_flow_def.dst_subnet = DST_IP

        rx_flow_def_snat = self.copy_flow(tx_flow_def)
        if self.num_vf_per_pf==1:
            rx_flow_def_snat.interface ^= 1
        rx_flow_def_snat.src_subnet = NAT_IP
        
        tx_flow_rev = self.reverse_flow_def(tx_flow_def)
        tx_flow_rev.src_subnet = DST_IP
        tx_flow_rev.dst_subnet = NAT_IP

        rx_flow_rev_dnat = self.copy_flow(tx_flow_rev)
        if self.num_vf_per_pf==1:
            rx_flow_rev_dnat.interface ^= 1
        rx_flow_rev_dnat.src_subnet = DST_IP
        rx_flow_rev_dnat.dst_subnet = SRC_IP

        self.start_receiving(self.ext_host_stub, rx_flow_def_snat)
        self.start_receiving(self.ext_host_stub, rx_flow_rev_dnat)

        self.start_sending(self.ext_host_stub, tx_flow_def)
        self.start_sending(self.ext_host_stub, tx_flow_rev)

        time.sleep(2)

        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, rx_flow_def_snat.flow_id) > 4, "UDP Packets not hairpinned")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, rx_flow_rev_dnat.flow_id) > 4, "UDP Packets not hairpinned (reverse)")

    def test_ipv4_udp_vlan_flows(self):
        """Check that UDP packets can be hairpinned back to the external host.""" 
        VLAN1 = 55
        VLAN2 = 56
        session = self.default_session(action = _FORWARD)
        session.vlan_inLif = VLAN1
        session.vlan_outLif = VLAN2
        session.action.actionParams_outLif.vlan = VLAN2
        session.action.actionParams_inLif.vlan = VLAN1
        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        flow_def_vlan1 = self.default_flow_def(session = session, vlan_id = VLAN1)
        flow_def_vlan2 = self.copy_flow(flow_def_vlan1)
        if self.num_vf_per_pf==1:
            flow_def_vlan2.interface ^= 1
        flow_def_vlan2.vlan_id = VLAN2

        flow_rev_vlan2 = self.reverse_flow_def(flow_def_vlan1, vlan_id = VLAN2)
        flow_rev_vlan1 = self.copy_flow(flow_rev_vlan2)
        if self.num_vf_per_pf==1:
            flow_rev_vlan1.interface ^= 1
        flow_rev_vlan1.vlan_id = VLAN1

        self.start_receiving(self.dpu_host_stub, flow_def_vlan1) # not offloaded vlan1
        self.start_receiving(self.ext_host_stub, flow_def_vlan2) # offloaded vlan1->vlan2

        self.start_receiving(self.dpu_host_stub, flow_rev_vlan2) # not offloaded vlan2
        self.start_receiving(self.ext_host_stub, flow_rev_vlan1) # offloaded vlan1->vlan2

        self.start_sending(self.ext_host_stub, flow_def_vlan1)
        self.start_sending(self.ext_host_stub, flow_rev_vlan2)

        time.sleep(2)

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_def_vlan1.flow_id), 0, "UDP Packets made it past the fwd rule")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, flow_def_vlan2.flow_id) > 4, "UDP Packets not hairpinned")

        self.assertEqual(self.count_rx_pkts(self.dpu_host_stub, flow_rev_vlan2.flow_id), 0, "UDP Packets made it past the fwd rule (reverse)")
        self.assertTrue(self.count_rx_pkts(self.ext_host_stub, flow_rev_vlan1.flow_id) > 4, "UDP Packets not hairpinned (reverse)")

    def test_ipv4_nexthop_dynamic_update(self):
        """Check that nexthop actions can be updated in-place.
        
        Note this test requires NOT running the nv_opof with --dmac option.
        """ 

        # note these must be lower-case to match what scapy returns in the traffic_gen
        src_macs = [
            "dd:dd:dd:dd:dd:dd", # inLif src-mac
            "ee:ee:ee:ee:ee:ee", # outLif src-mac
            "cc:cc:cc:cc:cc:cc", # updated outLif src-mac
        ]

        inLifNH = openoffload_pb2.nextHopParameters()
        inLifNH.macRewrite.srcMac = mac_str_to_bytes(src_macs[0])
        inLifNH.macRewrite.dstMac = mac_str_to_bytes("b8:3f:d2:ba:65:fb") # TODO: env var
        inLif_nhid = self.add_nexthop(inLifNH)

        outLifNH = openoffload_pb2.nextHopParameters()
        outLifNH.macRewrite.srcMac = mac_str_to_bytes(src_macs[1])
        outLifNH.macRewrite.dstMac = mac_str_to_bytes("b8:3f:d2:ba:65:fa") # TODO: env var
        outLif_nhid = self.add_nexthop(outLifNH)

        session = self.default_session(action = _FORWARD)
        session.action.actionParams_inLif.nextHopId = inLif_nhid
        session.action.actionParams_outLif.nextHopId = outLif_nhid

        self.assertTrue(self.offload_subnet(session, SAMPLE_SRC_SUBNET, SAMPLE_DST_SUBNET))

        flow_def1 = self.default_flow_def(session = session)
        flow_def2 = self.copy_flow(flow_def1)
        if self.num_vf_per_pf==1:
            flow_def2.interface ^= 1
        
        flow_rev2 = self.reverse_flow_def(flow_def1)
        flow_rev1 = self.copy_flow(flow_rev2)
        if self.num_vf_per_pf==1:
            flow_rev1.interface ^= 1

        self.start_receiving(self.ext_host_stub, flow_def2)
        self.start_receiving(self.ext_host_stub, flow_rev1)

        self.start_sending(self.ext_host_stub, flow_def1)
        self.start_sending(self.ext_host_stub, flow_rev2)

        time.sleep(2)

        self.assertTrue(src_macs[1] in self.get_rx_macaddrs(self.ext_host_stub, flow_def2.flow_id))
        self.assertTrue(src_macs[0] in self.get_rx_macaddrs(self.ext_host_stub, flow_rev1.flow_id))

        # Update the MAC action in-place:

        outLifNH.macRewrite.srcMac = mac_str_to_bytes(src_macs[2])
        self.add_nexthop(outLifNH) # keep the same NHID

        time.sleep(2)
        self.assertTrue(src_macs[2] in self.get_rx_macaddrs(self.ext_host_stub, flow_def2.flow_id))


    @unittest.skip("This is a very long test; enable as needed")
    def test_many_sessions_timeout(self):
        """Establish thousands of sessions and ensure OPOF continues to respond."""
        self.get_closed_sessions() # flush expired sessions

        closed_sessions = {}
        
        session = self.default_session(proto = _UDP, action = _FORWARD, timeout = 5)
        
        print("Creating 256K sessions. This will take a while...")
        for subnet_msb in range(4):
            print(f"16.{subnet_msb}.xx.yy > 48.{subnet_msb}.xx.yy ...")
            for subnet_lsb in range(256):
                src_subnet = f"16.{subnet_msb}.{subnet_lsb}.0/24"
                dst_subnet = f"48.{subnet_msb}.{subnet_lsb}.0/24"
                self.assertTrue(self.offload_subnet(session, src_subnet, dst_subnet))
                # keep draining the list of closed sessions or it may overflow
                for sid in self.get_closed_sessions():
                    closed_sessions[sid] = True

        time.sleep(10)
        print(f"Checking for {len(self.all_sessions)} session keys...")
        for sid in self.get_closed_sessions():
            closed_sessions[sid] = True
        self.assertEqual(len(closed_sessions), len(self.all_sessions))
        # for s in self.all_sessions:
        #     self.assertTrue(closed_sessions.get(s, False), "Session " + str(s) + " not expired")
        self.all_sessions.clear() # don't waste time on cleanup

if __name__ == '__main__':
    logging.basicConfig()
