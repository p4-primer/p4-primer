#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

struct metadata {
    bit<16> dst_port; 
    bit<16> src_port; 
    ipv4_addr_t next_hop;
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
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.dst_port = hdr.tcp.dst_port;
        meta.src_port = hdr.tcp.src_port;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.dst_port = hdr.udp.dst_port;
        meta.src_port = hdr.udp.src_port;
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
    action ecmp_route_select_next_hop(ipv4_addr_t next_hop) {
        meta.next_hop = next_hop; 
    }

    action_selector(HashAlgorithm.crc16, 32w1024, 32w4) as;

    table ecmp_route_tbl {
        key = {
            hdr.ipv4.dst_addr : lpm;
            hdr.ipv4.dst_addr : selector;
            hdr.ipv4.src_addr : selector;
            hdr.ipv4.protocol: selector;
            meta.dst_port : selector;
            meta.src_port : selector;
        }
        actions = {
            ecmp_route_select_next_hop;
        }
        implementation = as;
        size = 1024;
    }

    action fwd(bit<9> port_id, mac_addr_t dst_addr, mac_addr_t src_addr) {
        standard_metadata.egress_spec = port_id;
        hdr.ethernet.dst_addr = dst_addr; 
        hdr.ethernet.src_addr = src_addr; 
    }

    table fwd_tbl {
        key = {
            meta.next_hop : exact;
        }
        actions = {
            fwd;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    apply {
        if (hdr.ipv4.ttl == 0) {
            mark_to_drop(standard_metadata);
            exit;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if (ecmp_route_tbl.apply().hit) {
            fwd_tbl.apply();
        }
    }
}

control MyEgress(inout header_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
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
