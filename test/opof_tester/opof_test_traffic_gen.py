""" Python Implementation of the OPOF Traffic Gen Service """

from concurrent import futures
import argparse
import ipaddress
import logging
import sys
import time
import threading
import unittest

from scapy.all import Dot1Q, Ether, IP, IPv6, TCP, UDP, Raw, sendp, sniff, get_if_hwaddr, get_if_list

import grpc
import opof_tester_pb2
import opof_tester_pb2_grpc

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

class FlowDef:
    def __init__(self, flowDefMsg):
        self.flow_id    = flowDefMsg.flow_id
        self.interface  = flowDefMsg.interface
        self.transmit   = flowDefMsg.transmit
        self.vlan_id    = flowDefMsg.vlan_id
        self.eth_type   = flowDefMsg.eth_type
        self.proto      = flowDefMsg.proto
        self.dmac_idx   = flowDefMsg.dmac_idx
        self.src_subnet = ipaddress.ip_network(flowDefMsg.src_subnet)
        self.dst_subnet = ipaddress.ip_network(flowDefMsg.dst_subnet)
        self.src_port   = flowDefMsg.src_port
        self.dst_port   = flowDefMsg.dst_port
        self.tcp_flags  = flowDefMsg.tcp_flags
        self.payload_length = flowDefMsg.payload_length
        self.duration   = flowDefMsg.duration
        self.max_pps    = flowDefMsg.max_pps
        # For 'transmit' FlowDefs, increments with each packet sent to
        # create traffic variations.
        # For non-transmit, increments with each matching packet received.
        self.count      = 0
        # Keep track of all src-mac/dst-mac addresses received
        self.src_macs = dict()
        self.dst_macs = dict()

    def src_ip(self):
        return self._counter_to_ip_str(self.count, self.src_subnet)

    def dst_ip(self):
        return self._counter_to_ip_str(self.count, self.dst_subnet)

    def _counter_to_ip_str(self, count, subnet):
        return str(ipaddress.ip_address((count & int(subnet.hostmask)) | int(subnet.network_address)))
    
    def is_match(self, vlan, src_ip, dst_ip, sport, dport, proto, tcp_flags):
        # print(f"{vlan=} =? {self.vlan_id}")
        # print(f"{sport=} =? {self.src_port}")
        # print(f"{dport=} =? {self.dst_port}")
        # print(f"{proto=} =? {self.proto}")
        # print(f"{tcp_flags=} =? {self.tcp_flags}")
        # print(f"{src_ip=} in subnet {self.src_subnet}")
        # print(f"{dst_ip=} in subnet {self.dst_subnet}")
        result = (
            vlan == self.vlan_id and
            sport == self.src_port and
            dport == self.dst_port and
            proto == self.proto and
            self._tcp_flags_match(tcp_flags) and
            self._is_addr_match(src_ip, self.src_subnet) and
            self._is_addr_match(dst_ip, self.dst_subnet))
        #print(f"is_match: {self.flow_id=}, {result=}")
        return result

    def _debug_match(self, src_ip, dst_ip, sport, dport, proto, tcp_flags):
        match = dict()
        match['sport'] == self.src_port
        match['dport'] == self.dst_port
        match['proto'] == self.proto
        match['tcp_flags'] = self._tcp_flags_match(tcp_flags)
        match['src_subnet'] = self._is_addr_match(src_ip, self.src_subnet)
        match['dst_subnet'] = self._is_addr_match(dst_ip, self.dst_subnet)
        return match

    def _is_addr_match(self, ip, subnet):
        ip = int(ipaddress.ip_address(ip)) # string to integer
        return (ip & int(subnet.netmask)) == int(subnet.network_address)
    
    def _tcp_flags_match(self, tcp_flags):
        return (self.tcp_flags & tcp_flags) == self.tcp_flags
        

class TrafficGenerator(opof_tester_pb2_grpc.OpofTrafficGenServicer):
    def __init__(self, name, interfaces, dmac, vlan, shutdown):
        self.trace = False
        self.exit = False
        self.name = name
        self.tx_flow_lock = threading.Lock()
        self.rx_flow_lock = threading.Lock()
        self.tx_flows = dict()
        self.rx_flows = dict()
        self.shutdown = shutdown
        self.interfaces = interfaces.split(',')
        self.dmac = dmac.split(',')
        self.vlan = int(vlan) if vlan is not None and len(vlan) > 0 else 0

        self.my_macs = [get_if_hwaddr(i) for i in self.interfaces]

        self.traffic_gen_thread = threading.Thread(target=lambda: self.SendTraffic())
        self.sniff_threads = []
        for idx, iface in enumerate(self.interfaces):
            self.sniff_threads.append(threading.Thread(target=lambda idx=idx: self.SniffTraffic(idx)))

        self.traffic_gen_thread.start()
        for sniff_thread in self.sniff_threads:
            sniff_thread.start()
    
    def ProcessHeartbeat(self, request, context):
        if request.shutdown:
            print(f"{self.name}: Shutting down...")
            self.exit = True
            self.shutdown()
        return request
    
    def AddFlow(self, request, context):
        response = self.FlowAck(request)
        if request.eth_type == opof_tester_pb2._IPV4:
            flow = FlowDef(request)
            if flow.transmit:
                with self.tx_flow_lock:
                    self.tx_flows[flow.flow_id] = flow
            else:
                with self.rx_flow_lock:
                    self.rx_flows[flow.flow_id] = flow
        return response
    
    def RemoveFlow(self, request, context):
        response = self.FlowAck(request)

        with self.tx_flow_lock:
            if request.flow_id == -1:
                self.tx_flows.clear()
                response.success = True
            elif request.flow_id in self.tx_flows:
                del self.tx_flows[request.flow_id]
                response.success = True
        with self.rx_flow_lock:
            if request.flow_id == -1:
                self.rx_flows.clear()
                response.success = True
            elif request.flow_id in self.rx_flows:
                del self.rx_flows[request.flow_id]
                response.success = True
        
        if not response.success:
            response.reason = "Flow not found"
        return response
    
    def FlowAck(self, request):
        response = opof_tester_pb2.FlowResponse()
        response.flow_id = request.flow_id
        response.success = True
        return response

    def GetFlowStats(self, request, context):
        response = opof_tester_pb2.FlowStats()
        with self.rx_flow_lock:
            for [flow_id, flow] in self.rx_flows.items():
                stats = response.stats[flow_id]
                stats.subnet_count = flow.count
                stats.src_macs.extend(list(flow.src_macs.keys()))
                stats.dst_macs.extend(list(flow.dst_macs.keys()))
        return response
    
    def SendTraffic(self):
        while not self.exit:
            #print(f"{self.name}: Sending traffic...")
            for i, iface in enumerate(self.interfaces):
                smac = get_if_hwaddr(iface)
                pkts = []
                with self.tx_flow_lock:
                    for [flow_id, flow] in self.tx_flows.items():
                        if flow.transmit and flow.interface==i:
                            pkts.append(self.MakePacket(flow, smac))
                            flow.count += 1
                sendp(pkts, iface=iface, verbose=0)
            #time.sleep(0.001)
    
    def MakePacket(self, flow, smac):
        if flow.dmac_idx >= len(self.dmac):
            print(f"Warning: commanded dmac_idx {flow.dmac_idx}, but self.dmac = {self.dmac}")
            flow.dmac_idx = 0
        pkt = Ether(src=smac, dst=self.dmac[flow.dmac_idx])

        if flow.vlan_id > 0:
            # flow-specific vlan takes precedence
            pkt = pkt/Dot1Q(vlan=flow.vlan_id)
        elif self.vlan > 0:
            # fall-back to global vlan if present
            pkt = pkt/Dot1Q(vlan=self.vlan)
        
        if flow.eth_type == opof_tester_pb2._IPV4:
            pkt = pkt/IP(src=flow.src_ip(), dst=flow.dst_ip())
        elif flow.eth_type == opof_tester_pb2._IPV6:
            pkt = pkt/IPv6(src=flow.src_ip(), dst=flow.dst_ip())

        if flow.proto == opof_tester_pb2._TCP:
            pkt = pkt/TCP(sport=flow.src_port, dport=flow.dst_port, flags=flow.tcp_flags)
        elif flow.proto == opof_tester_pb2._UDP:
            pkt = pkt/UDP(sport=flow.src_port, dport=flow.dst_port)
        
        pkt = pkt/('\0' * flow.payload_length)
        return pkt

    def SniffTraffic(self, iface_idx):
        print(f"{self.name}: Listening for traffic on {self.interfaces[iface_idx]}")

        # Packets with our own source mac will be excluded.
        # This assumes the OPOF agent will re-write the smac
        # before hairpinning the traffic.

        while not self.exit:
            packets = sniff(
                iface=self.interfaces[iface_idx], 
                timeout=0.1, 
                prn=lambda pkt: self.ProcessSniffedPacket(pkt, iface_idx, self.my_macs[iface_idx]))
    
    def ProcessSniffedPacket(self, pkt, iface_idx, smac_filter):
        has_vlan = pkt.haslayer(Dot1Q)
        is_ipv4 = pkt.haslayer(IP)
        is_ipv6 = pkt.haslayer(IPv6)
        if not (is_ipv4 or is_ipv6):
            return
        is_tcp = pkt.haslayer(TCP)
        is_udp = pkt.haslayer(UDP)
        if not (is_tcp or is_udp):
            return

        ether = pkt.getlayer(Ether)
        vlan = pkt.getlayer(Dot1Q).vlan if has_vlan else 0
        ip_layer = pkt.getlayer(IP) if is_ipv4 else pkt.getlayer(IPv6)
        pkt_src = ip_layer.src
        pkt_dst = ip_layer.dst
        proto_layer = pkt.getlayer(TCP) if is_tcp else pkt.getlayer(UDP)
        pkt_sport = proto_layer.sport
        pkt_dport = proto_layer.dport
        pkt_proto = opof_tester_pb2._TCP if is_tcp else opof_tester_pb2._UDP
        tcp_flags = int(pkt['TCP'].flags) if is_tcp else 0
        proto_name = "TCP" if is_tcp else "UDP"
        if pkt.src in smac_filter:
            if self.trace:
                print(f"{self.name}: Ignoring {proto_name} packet from my own mac: {pkt.src} > {pkt.dst}, {pkt_src}:{pkt_sport} > {pkt_dst}:{pkt_dport}")
            return
        if self.trace:
            print(f"{self.name}: Got a {proto_name} packet on iface {iface_idx} vlan {vlan}: {pkt.src} > {pkt.dst}, {pkt_src}:{pkt_sport} > {pkt_dst}:{pkt_dport}")
        with self.rx_flow_lock:
            found = False
            for [flow_id, flow] in self.rx_flows.items():
                if (flow.interface == iface_idx and
                    not flow.transmit and
                    flow.is_match(vlan, pkt_src, pkt_dst, pkt_sport, pkt_dport, pkt_proto, tcp_flags)
                ):
                    if flow.count == 0 and self.trace:
                        print(f"{self.name}: Found a pkt matching flow {flow.flow_id}")
                    flow.count += 1
                    flow.src_macs.setdefault(ether.src, 1)
                    flow.dst_macs.setdefault(ether.dst, 1)
                    found = True
        if self.trace and not found and len(self.rx_flows) > 0:
            print(f"{self.name}: No matching flow: iface {iface_idx}: {proto_name}: {pkt_src}:{pkt_sport} > {pkt_dst}:{pkt_dport}, flags '{tcp_flags}', searched {len(self.rx_flows)} flows")

def serve():
    parser = argparse.ArgumentParser(description='OPOF Test Traffic Generator')
    parser.add_argument('-n', '--name', required=True, help="Service name to appear in logs")
    parser.add_argument('-i', '--interfaces', required=True, help="Comma-separated list of enet interface names")
    parser.add_argument('-d', '--dmac', required=True, help="Comma-separated list of dmac destinations")
    parser.add_argument('-v', '--vlan', required=False, help="VLAN TCI (optional)")
    args = parser.parse_args()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    shutdown = lambda: server.stop(1)
    print(f"{args.name}: Using interfaces {args.interfaces}")
    print(f"{args.name}: Using dmac {args.dmac}")
    print(f"{args.name}: Using vlan {args.vlan}")
    opof_tester_pb2_grpc.add_OpofTrafficGenServicer_to_server(
        TrafficGenerator(args.name, args.interfaces, args.dmac, args.vlan, shutdown), server)
    addr = '[::]:3444'
    server.add_insecure_port(addr)
    server.start()
    print(f"{args.name}: Listening on {addr}...")
    server.wait_for_termination()

class TestSubnets(unittest.TestCase):
    # Suggest running with:
    # pytest opof_test_traffic_gen.py

    def default_request(self):
        req = FlowDefinition
        req.flow_id = 1234
        req.interface = 0
        req.transmit = False
        req.eth_type = opof_tester_pb2._IPV4
        req.proto = opof_tester_pb2._TCP
        req.src_subnet = "10.10.0.0/16"
        req.dst_subnet = "20.20.20.0/24"
        req.src_port = 55
        req.dst_port = 66
        req.payload_length = 1024
        req.duration = 0
        req.max_pps = 0
        return req
    
    def default_ipv6_request(self):
        req = self.default_request()
        req.src_subnet = "2001:db00::0/32"
        req.dst_subnet = "fefe:bdbd:8787::0/48"
        return req

    def test_ipv4_subnet_matching(self):
        flow = FlowDef(self.default_request())
        self.assertTrue(flow._is_addr_match('10.10.0.1', flow.src_subnet))
        self.assertTrue(flow._is_addr_match('10.10.255.1', flow.src_subnet))
        self.assertFalse(flow._is_addr_match('10.11.0.1', flow.src_subnet))

    def test_ipv6_subnet_matching(self):
        flow = FlowDef(self.default_ipv6_request())
        lower96 = ':'.join(['1234:5678'] * 3)
        self.assertTrue( flow._is_addr_match('2001:db00:' + lower96, flow.src_subnet))
        self.assertFalse(flow._is_addr_match('2001:db01:' + lower96, flow.src_subnet))

    def test_ipv4_addr_gen(self):
        flow = FlowDef(self.default_request())
        flow.count = 8
        self.assertEqual(flow.src_ip(), "10.10.0.8")
        flow.count = 0x100 * 55 + 66
        self.assertEqual(flow.src_ip(), "10.10.55.66")
        flow.count = 0xffff0000 + 0x100 * 55 + 66
        self.assertEqual(flow.src_ip(), "10.10.55.66")

if __name__ == '__main__':
    logging.basicConfig()
    serve()
