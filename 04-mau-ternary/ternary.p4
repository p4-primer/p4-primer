#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

struct metadata {
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
    bit<16> dst_port; 
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
        meta.src_addr = hdr.ipv4.src_addr;
        meta.dst_addr = hdr.ipv4.dst_addr;
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.dst_port = hdr.udp.dst_port;
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
    action allow() {
        standard_metadata.egress_spec = 0x2;
    }

    action deny() {
        mark_to_drop(standard_metadata);
    }

    table acl_tbl {
        key = {
            meta.src_addr : ternary; 
            meta.dst_addr : ternary; 
            meta.dst_port : ternary; 
        }
        actions = {
            allow;
            deny;
        }
        size = 1024;
        default_action = deny();
    }

    apply {
        if (hdr.ipv4.ttl == 0) {
            mark_to_drop(standard_metadata);
            exit;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        acl_tbl.apply();
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
