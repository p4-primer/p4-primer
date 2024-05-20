#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;

header Ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

struct metadata { }

struct headers {
    Ethernet_h eth;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.eth);
        transition accept;
    }
}

control MyChecksum(inout headers hdr, inout metadata meta)
{
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    action set_dst_addr() {
        hdr.eth.dstAddr = 0xaabbccddee02;
        standard_metadata.egress_spec = 0x2;
    }

    table mac_match_tbl {
        key = {
            hdr.eth.dstAddr : exact; 
        }
        actions = {
            set_dst_addr;
            NoAction;
        }

        const entries = {(0x112233445566) : set_dst_addr(); }
        //size = 1024;
        default_action = NoAction();
    }
    apply {
        mac_match_tbl.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}

control MyDeparserChecksum(inout headers hdr, inout metadata meta)
{
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr)
{
    apply {
        packet.emit(hdr.eth);
    }
}

V1Switch(
    MyParser(),
    MyChecksum(),
    MyIngress(),
    MyEgress(),
    MyDeparserChecksum(),
    MyDeparser()
) main;
