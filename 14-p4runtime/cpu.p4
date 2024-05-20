#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1

const bit<16> MAC_LEARNING_ETHER_TYPE = 0x8787;
const bit<32> CPU_HEADER_LENGHT = 22; // ethernet_h(14) + cpu_h(8)

const bit<8> METADATA_RESUBMIT_INDEX = 0;
struct metadata {
    @field_list(METADATA_RESUBMIT_INDEX)
    bit<9> ingress_port;
}

parser MyParser(packet_in packet,
                out header_t hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{

    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout header_t hdr, inout metadata meta)
{
    apply {  }
}

control MyIngress(inout header_t hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mac_learn()
    {
        meta.ingress_port = standard_metadata.ingress_port;
        clone_preserving_field_list(CloneType.I2E, 100, METADATA_RESUBMIT_INDEX);
    }

    table smac_tbl {
        key = {
            hdr.ethernet.src_addr: exact;
        }

        actions = {
            mac_learn;
            NoAction;
        }
        size = 1024;
        default_action = mac_learn;
    }

    action forward(bit<9> egress_port)
    {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac_tbl {
        key = {
            hdr.ethernet.dst_addr: exact;
        }

        actions = {
            forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    action set_multicaset_group(bit<16> multicast_group)
    {
        standard_metadata.mcast_grp = multicast_group;
    }

    table broadcast_tbl {
        key = {
            standard_metadata.ingress_port: exact;
        }

        actions = {
            set_multicaset_group;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
        smac_tbl.apply();
        if (dmac_tbl.apply().hit){
            //
        } else {
            broadcast_tbl.apply();
        }
    }
}

control MyEgress(inout header_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply {
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
            hdr.cpu.setValid();
            hdr.cpu.src_mac_addr = hdr.ethernet.src_addr;
            hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
            hdr.ethernet.ether_type = MAC_LEARNING_ETHER_TYPE;
            // ether+cpu header
            truncate((bit<32>)22);
        }
    }
}

control MyComputeChecksum(inout header_t hdr, inout metadata meta)
{
    apply { }
}

control MyDeparser(packet_out packet, in header_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

