#! /usr/bin/python3
import sys
from scapy.all import Ether, sniff, Packet, BitField, raw
import p4runtime_sh.shell as sh

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('macAddr',0,48), BitField('ingress_port', 0, 16)]

# packet_callback() is called once we capture a packet
def packet_callback(packet):
    packet = Ether(raw(packet))
    if packet.type == 0x8787:
        cpu_header = CpuHeader(bytes(packet.load))
        te = sh.TableEntry('smac_tbl')(action='NoAction')
        te.match['ethernet.src_addr'] = str(cpu_header.macAddr)
        te.insert()
        print("Insert an entry into smac_tbl, ethernet.src_addr: 0x%012x"
                % (cpu_header.macAddr))
        te = sh.TableEntry('dmac_tbl')(action='forward')
        te.match['ethernet.dst_addr'] = str(cpu_header.macAddr)
        te.action['egress_port'] = str(cpu_header.ingress_port)
        te.insert()
        print("Insert an entry into smac_tbl, ethernet.dst_addr: 0x%012x, egress_port: %s"
                % (cpu_header.macAddr, cpu_header.ingress_port))


# main

# connect with P4Runtime grpc server
sh.setup(
    device_id=0,
    grpc_addr='localhost:9559',
    election_id=(0, 1), # (high, low)
    config=sh.FwdPipeConfig('cpu.p4.p4info.txt', 'cpu.json')
)
print("Hello, P4Runtime grpc server connected !")

cse = sh.CloneSessionEntry(100)
cse.add(255, 100)
cse.insert()

mcge = sh.MulticastGroupEntry(1)
mcge.add(2, 1)
mcge.add(3, 1)
mcge.insert()

te = sh.TableEntry('broadcast_tbl')(action='set_multicaset_group')
te.match['standard_metadata.ingress_port'] = "1"
te.action['multicast_group'] = "1"
te.insert()

capture_device = "veth7"

print(f"Starting packet sniffer on device {capture_device}...")
print("Start mac learning!")
sniff(iface=capture_device, prn=packet_callback, count=1000)

sh.teardown()
