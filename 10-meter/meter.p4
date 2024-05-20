#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

const bit<32> PORT_MAX_NUMBER = 256;
const bit<32> L4_PROTOCOL_MAX_NUMBER = 256;

struct metadata { }

parser MyParser(packet_in pkt,
                out header_t hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout header_t hdr, inout metadata meta)
{
    apply {}
}

control MyIngress(inout header_t hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    apply {
        standard_metadata.egress_spec = 0x2;
    }
}

control MyEgress(inout header_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    bit<2> port_meter_result = V1MODEL_METER_COLOR_GREEN;
    direct_meter<bit<2>>(MeterType.packets) port_meter;

    action meter_action(){
        port_meter.read(port_meter_result);
    }

    table egress_port_tbl {
        key = {
            standard_metadata.egress_port : exact;
        }

        actions = {
            meter_action;
        }

        meters = port_meter;
        size = PORT_MAX_NUMBER;
        default_action = meter_action();
    }

    apply {
        egress_port_tbl.apply();
        if (port_meter_result >= V1MODEL_METER_COLOR_YELLOW) {
            mark_to_drop(standard_metadata);
        }
    }
}

control MyComputeChecksum(inout header_t hdr, inout metadata meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in header_t hdr)
{
    apply {
        packet.emit(hdr);
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
