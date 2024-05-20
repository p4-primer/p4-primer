#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

const bit<32> PORT_MAX_NUMBER = 256;
const bit<32> L4_PROTOCOL_MAX_NUMBER = 256;

struct metadata {
    bit<8> l4_protocol; 
}

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
        meta.l4_protocol = hdr.ipv4.protocol;
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
    direct_counter(CounterType.packets_and_bytes) port_counter;
    direct_counter(CounterType.packets_and_bytes) tcp_counter;
    counter(1, CounterType.packets_and_bytes) udp_counter;

    table ingress_port_counter_tbl {
        key = {
            standard_metadata.ingress_port : exact;
        }

        actions = {
            NoAction;
        }

        counters = port_counter;
        size = PORT_MAX_NUMBER;
        default_action = NoAction();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action fwd_tcp() {
        standard_metadata.egress_spec = 0x2;
    }

    table tcp_counter_tbl {
        key = {
            meta.l4_protocol : exact;
        }

        actions = {
            fwd_tcp;
            drop;
        }

        counters = tcp_counter;
        size = L4_PROTOCOL_MAX_NUMBER;
        default_action = drop();
    }

    apply {
        if (meta.l4_protocol == IP_PROTOCOLS_UDP) {
            udp_counter.count(0);
        }
        
        ingress_port_counter_tbl.apply();

        tcp_counter_tbl.apply();
    }
}

control MyEgress(inout header_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    counter(PORT_MAX_NUMBER, CounterType.packets_and_bytes) egress_counter;
    
    action counter_action(bit<9> port_id) {
        egress_counter.count((bit<32>)port_id);
    }

    table egress_port_counter_tbl {
        key = {
            standard_metadata.egress_spec : exact;
        }

        actions = {
            counter_action;
        }
        size = PORT_MAX_NUMBER;
        default_action = counter_action(0x2);
    }

    apply {
        egress_port_counter_tbl.apply();
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
