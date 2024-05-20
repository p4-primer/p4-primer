#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

enum bit<1> packet_direction_t {
    INTERNAL_TO_EXTERNAL = 0,
    EXTERNAL_TO_INTERNAL = 1
} 

struct metadata {
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
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
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
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;

    bit<32> reg_pos_one;
    bit<32> reg_pos_two;
    bit<1>  reg_val_one;
    bit<1>  reg_val_two;

    bit<1> direction = packet_direction_t.INTERNAL_TO_EXTERNAL;

    action compute_hashes(ipv4_addr_t ip1, ipv4_addr_t ip2,
                          bit<16> port1,
                          bit<16> port2) {
       // calculate register position
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0,
            {ip1,
             ip2,
             port1,
             port2,
             hdr.ipv4.protocol},
             (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0,
            {ip1,
             ip2,
             port1,
             port2,
             hdr.ipv4.protocol},
             (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action set_next_hop(ipv4_addr_t next_hop) {
        meta.next_hop = next_hop;
    }

    table l3_fwd_tbl {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            set_next_hop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action l2_fwd(bit<9> port_id, mac_addr_t dst_addr, mac_addr_t src_addr) {
        standard_metadata.egress_spec = port_id;
        hdr.ethernet.dst_addr = dst_addr; 
        hdr.ethernet.src_addr = src_addr; 
    }

    table l2_fwd_tbl {
        key = {
            meta.next_hop : exact;
        }
        actions = {
            l2_fwd;
            NoAction;
        }
        default_action = NoAction();
        size = 1024;
    }

    action set_direction(bit<1> dir) {
        direction = dir;
    }

    table port_acl_tbl {
        key = {
            standard_metadata.ingress_port : exact;
            standard_metadata.egress_spec  : exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (hdr.ipv4.ttl == 0) {
            mark_to_drop(standard_metadata);
            exit;
        }
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // l3 forward and l2 forward
        if (l3_fwd_tbl.apply().hit) {
            l2_fwd_tbl.apply();
        }

        // firewall
        if (hdr.tcp.isValid()){
            if (port_acl_tbl.apply().hit) {
                // test and set the bloom filter
                if (direction == packet_direction_t.INTERNAL_TO_EXTERNAL) {
                    compute_hashes(hdr.ipv4.src_addr, hdr.ipv4.dst_addr,
                                   hdr.tcp.src_port, hdr.tcp.dst_port);
                } else {
                    compute_hashes(hdr.ipv4.dst_addr, hdr.ipv4.src_addr,
                                   hdr.tcp.dst_port, hdr.tcp.src_port);
                }

                if (direction == packet_direction_t.INTERNAL_TO_EXTERNAL){
                    // If there is a syn we update the bloom filter
                    if (hdr.tcp.flags == TCP_FLAGS_SYN){
                        bloom_filter_1.write(reg_pos_one, 1);
                        bloom_filter_2.write(reg_pos_two, 1);
                    }
                } else if (direction == packet_direction_t.EXTERNAL_TO_INTERNAL){
                    bloom_filter_1.read(reg_val_one, reg_pos_one);
                    bloom_filter_2.read(reg_val_two, reg_pos_two);
                    // only allow flows to pass if both entries are set
                    if (reg_val_one != 1 || reg_val_two != 1){
                        drop();
                    }
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
