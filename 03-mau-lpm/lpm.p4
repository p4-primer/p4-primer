#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

struct metadata {
    ipv4_addr_t next_hop;
    mac_addr_t  next_hop_mac; 
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
    action set_next_hop(ipv4_addr_t next_hop) {
        meta.next_hop = next_hop;
    }

    table l3_fwd_tbl {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            set_next_hop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action set_next_hop_mac(mac_addr_t mac) {
        meta.next_hop_mac = mac;
    }

    table arp_tbl {
        key = {
            meta.next_hop: exact;
        }
        actions = {
            set_next_hop_mac;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action set_egress_port(bit<9> port_id) {
        standard_metadata.egress_spec = port_id;
    }

    table l2_fwd_tbl {
        key = {
            meta.next_hop_mac: exact;
        }
        actions = {
            set_egress_port;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.ttl == 0) {
            mark_to_drop(standard_metadata);
            exit;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if (l3_fwd_tbl.apply().hit) {
            if (arp_tbl.apply().hit) {
                if (l2_fwd_tbl.apply().hit) {
                    hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
                    hdr.ethernet.dst_addr = meta.next_hop_mac;
                }
            }
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
