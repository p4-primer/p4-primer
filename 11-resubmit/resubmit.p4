#include <core.p4>
#include <v1model.p4>

#include "headers.p4"

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_RECIRCULATE 4
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<8> METADATA_RESUBMIT_INDEX = 0;
const bit<8> METADATA_RECIRCULATE_INDEX = 1;

struct metadata {
    @field_list(METADATA_RESUBMIT_INDEX)
    bit<8> ttl_1;
    @field_list(METADATA_RECIRCULATE_INDEX)
    bit<8> ttl_2;
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
    apply {
        standard_metadata.egress_spec = 0x2;
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
            if (hdr.ipv4.ttl == 128) {
                hdr.ipv4.ttl = 32;
                meta.ttl_1 = 32;
                resubmit_preserving_field_list(METADATA_RESUBMIT_INDEX);
            }
        } else if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_RESUBMIT) {
            hdr.ipv4.identification = (bit<16>)(meta.ttl_1);
        } else if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_RECIRCULATE) {
            hdr.ipv4.identification = (bit<16>)(meta.ttl_2);
        }
    }
}

control MyEgress(inout header_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply {
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
            if (hdr.ipv4.ttl == 64) {
                hdr.ipv4.ttl = 16;
                meta.ttl_2 = 16;
                recirculate_preserving_field_list(METADATA_RECIRCULATE_INDEX);
            }
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
