# Summary of nv_opof Flows

The `nv_opof` service makes extensive use of DPDK [rte_flow](https://doc.dpdk.org/guides/prog_guide/rte_flow.html) to achieve OpenOffload functionality.

Flows in DPDK are divided into the following `domains`:
- `transfer` (aka Flow Database)
- `ingress`
- `egress` _(not used)_

Within a domain, any number of `groups` may exist, each with any number of `flows`, each of which contains a match condition and a series of actions, which may include jumping to other `groups`, forwarding a packet to a port, or dropping the packet, and much more.

Flow `group` tables are independently numbered in each `domain`; e.g. flows in `group 0` in the `ingress domain` have nothing to do with flows in `group 0` in the `transfer domain`.

Within each `group`, flows can have individual priorities, with 0 being the highest. The lowest priority depends on the `group` number; namely, for ConnectX/BlueField devices, `group 0` has fewer possible priorities (0..4) than non-zero `groups`.

When a packet follows a `jump` command to a `group` that doesn't exist (no flow entries exist for that `group`), the packet executes the "miss" action, which is the usual way to transition from `transfer` to `ingress` to `egress` domains.

The following diagram illustrates how these domains are connected, forming the path for a packet on a single Physical Function (PF). In reality, there are two PFs, and each includes all the domains and paths shown below.
```
(Repeat for p1/pf1vf1 attached to vFW eth2)

      +--------------+ VM
      |              |
      |              |
      |      vFW     |
      +---|--------|-+
          | eth1   | eth2
          |       ...
          |                     Host
----------|-------------------------
          |                      DPU
          |
          + pf0vf0 repr
     +----------+   +----------+   ++-----++   +---------+
     | e-switch |   | p0 NIC   |   ||     ||   | p1 NIC  |
     | xfer     |-->| ingress  |-->|| HPQ ||-->| egress  |------->
     | domain   |   | domain   |   ||     ||   | domain  | PF1
     +----------+   +----------+   ++-----++   +---------+ uplink
          + p0 repr
          |
<---------+
PF0 uplink

```

In `nv_opof`, packets ingressing from the outside world (via the Uplink port representors) and from the virtual firewall (vFW) (via VF representors) are first processed in the embedded switch (e-switch) in the `transfer` domain. From there, if **no** matching forward/drop rules exist, they are forwarded from uplink to VF, or VF to uplink. Note it is not possible to directly forward packets from uplink to uplink; this requires the use of hairpin queues from the `ingress domain`.

Forwarding actions between the uplink ports and the VF ports are achieved by creating `port_id` actions within the `transfer domain`. Forwarding actions between the two uplinks are achieved by creating `queue` actions within the `ingress domain`, and specifying the indices of hairpin queues.

VLAN functionality is applied via flows at the `transfer domain`, at a lower priority than forwarding Session flows. Flows from each uplink may be given VLAN IDs which should be forwarded to specific VFs.

Session flows (which forward or drop packets) are complex, and occur in the `transfer domain`. They are bi-directional; e.g. client-to-server and server-to-client, so require the creation of two flows, with the second having source and destination fields all swapped. The match conditions include:
- a VLAN tag (optional)
- IPv4 or IPv6 src and dest addresses
- TCP or UDP src and dest port numbers

The actions may include:
- IP address re-writes
- TCP/UDP port number re-writes

If NAT is enabled, then the server-to-client match rules must be modified to account for the translated addresses and port numbers. Additional actions include:
- aging
- counting
- modifying the VLAN tag (optional)
- jumping to the `ingress domain`, where the next destination is a hairpin queue

In order for the `ingress domain` to send incoming packets to the correct set of hairpin queues, the `transfer domain` marks the packet with a `meta` bit indicating which hairpin queue set is to be `RSS`ed to. This overcomes the limitation where session matching must occur in the `ingress domain` (so miss packets can route to the VF) and hairpinning must occur in the `ingress domain`. However, it requires a special `mlx5` devarg: `dv_xmeta_en=2` so that meta bits survive when crossing domain boundaries.

The `meta` word is also used to carry the `next-hop` ID to the next `group`, which contains mappings from next-hop IDs to the src/dst MAC addresses to write to the packet headers. Because the 32-bit `meta` word carries both the hairpin queue indicator and the next-hop ID, the next-hop ID is limited to 30 bits.

## More about Hairpin Queues

To achieve maximum forwarding performance, four hairpin queues are created, and flows are `RSS`ed across them, similarly to how RSS would normally spread loads across CPU cores via normal DPDK queues. Experimentation on BlueField 2 led to the choice of 4 hairpin queues and default devargs for maximum throughput. This combination may not be optimal for later generations of hardware.

To achieve forwarding from either uplink to either uplink, two sets of RSS queues are created. One set (of four) associates the uplink to itself, and the other set associates to the opposite uplink. Selecting to RSS to indices 1..4 or 5..8 determines which uplink will transmit the forwarded packet.

## Order of flow tables

### Transfer Domain

#### Group 0

This group contains a single flow: jump to group 1. This overcomes limitations with group 0.

#### Group 1

The lowest priority flows in Group 1 are the "to-uplink" flows, which route session traffic from the vFW VF (after inspection) to the associated uplink. _(We may optionally insert a VLAN tag on the way up to the vFW, but this feature is not used.)_

The "Fdb miss" flows are also inserted here, to capture packets which do not yet match any Sessions and forward them to the appropriate vFW FW. _(If multiple VFs exist per PF, then we may specify a matching VLAN tag to indicate which VF we wish to forward to, in which case the VLAN tag is removed before sending to the vFW. This is not used.)_

VLAN Flows are inserted here, at a lower priority than Session flows but higher priority than non-VLAN-tagged flows. If multiple VFs exist per PF, then we may specify a matching VLAN tag to indicate which VF we wish to forward to. The VLAN tag is not stripped.

This is also the group where all Session flows are created (both directions). These flows receive a higher priority than the default flows described above. If the Session flows specify a next-hop ID, then the next destination is Group 2. Otherwise, the packet is forwarded to the NIC Ingress domain.

#### Group 2

Next-hop flows go here, to overwrite src/dst MAC addresses. The packet is then forwarded to the NIC Ingress domain.

### NIC Ingress Domain

#### Group 0

This group contains two flows, one for each `meta` tag, to forward packets to each set of hairpin queues. The `rss` action is configured to hash the IP and UDP/TCP packet fields to maximize entropy and spread load across the queues.

If the command-line arguments specify overwriting a dest MAC address (i.e. for testing), that packet mod is applied here.


