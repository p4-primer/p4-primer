#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

struct metadata { }

parser MyParser(packet_in pkt,
                out header_t hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        pkt.extract(hdr.inner_eth);
        transition select(hdr.inner_eth.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.inner_ipv4);
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
    action add_tunnel_header(mac_addr_t mac_src_addr,
                            mac_addr_t mac_dst_addr,
                            ipv4_addr_t tunnel_src_addr,
                            ipv4_addr_t tunnel_dst_addr,
                            bit<24> vni)
    {
        hdr.outer_eth.setValid();
        hdr.outer_eth.src_addr = mac_src_addr;
        hdr.outer_eth.dst_addr = mac_dst_addr;
        hdr.outer_eth.ether_type = ETHERTYPE_IPV4;
        
        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.src_addr = tunnel_src_addr;
        hdr.outer_ipv4.dst_addr = tunnel_dst_addr;
        hdr.outer_ipv4.version = 4;
        hdr.outer_ipv4.ihl = 5;
        hdr.outer_ipv4.diffserv = 0;
        hdr.outer_ipv4.total_len = hdr.inner_ipv4.total_len
                                 + ETH_HEADER_LEN
                                 + VXLAN_HEADER_LEN
                                 + UDP_HEADER_LEN
                                 + IPV4_HEADER_LEN;
        hdr.outer_ipv4.identification = 0; 
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.frag_offset = 0;
        hdr.outer_ipv4.ttl = 64;
        hdr.outer_ipv4.protocol = IP_PROTOCOLS_UDP;
        
        hdr.outer_udp.setValid();
        hdr.outer_udp.src_port = 10000;
        hdr.outer_udp.dst_port = UDP_PORT_VXLAN;
        hdr.outer_udp.hdr_length = hdr.inner_ipv4.total_len
                                 + ETH_HEADER_LEN
                                 + VXLAN_HEADER_LEN
                                 + UDP_HEADER_LEN;
        hdr.outer_udp.checksum = 0;

        hdr.vxlan.setValid();
        hdr.vxlan.flags = VXLAN_FLAGS;
        hdr.vxlan.reserved = 0;
        hdr.vxlan.vni = vni;
        hdr.vxlan.reserved2 = 0;

        standard_metadata.egress_spec = 0x2;
    }

    table vxlan_tbl {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.inner_ipv4.dst_addr: exact; 
        }
        actions = {
            add_tunnel_header;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        vxlan_tbl.apply();
    }
}   

control MyEgress(inout header_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply {}
}

control MyComputeChecksum(inout header_t hdr, inout metadata meta)
{
    apply {
        update_checksum(
            hdr.outer_ipv4.isValid(),
            { hdr.outer_ipv4.version,
              hdr.outer_ipv4.ihl,
              hdr.outer_ipv4.diffserv,
              hdr.outer_ipv4.total_len,
              hdr.outer_ipv4.identification,
              hdr.outer_ipv4.flags,
              hdr.outer_ipv4.frag_offset,
              hdr.outer_ipv4.ttl,
              hdr.outer_ipv4.protocol,
              hdr.outer_ipv4.src_addr,
              hdr.outer_ipv4.dst_addr
            },
            hdr.outer_ipv4.hdr_checksum,
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
