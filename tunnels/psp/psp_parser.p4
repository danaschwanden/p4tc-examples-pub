#include <core.p4>
#include <tc/pna.p4>

struct metadata_t {
    @tc_type("ipv4") bit<32> src;
    @tc_type("ipv4") bit<32> dst;
    bool    push;
}

header ethernet_t {
    @tc_type("macaddr") bit<48> dstAddr;
    @tc_type("macaddr") bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    @tc_type("ipv4") bit<32> srcAddr;
    @tc_type("ipv4") bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header psp_t {
    bit<8>  nextHeader;
    bit<8>  hdrExtLen;
    bit<2>  res;
    bit<6>  cryptOffset;
    bit<1>  cryptOffset;
    bit<1>  sample;
    bit<1>  drop;
    bit<4>  version;
    bit<1>  virtCookie;
    bit<32> spi;
    bit<64> initVector;
}

header pspvc_t {
    bit<64> cookie;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     enc_ip;
    udp_t      enc_udp;
    ipv4_t     inner;
    psp_t      psp;
    pspvc_t    pspvc;
}

#define ETHERTYPE_IPV4 0x0800
#define IP_PROTO_IPV4 0x4
#define IP_PROTO_TCP 0x6
#define IP_PROTO_UDP 0x11
#define VIRT_COOKIE 0x1

/***********************  P A R S E R  **************************/
parser Parser(
        packet_in pkt,
        out   headers_t  hdr,
        inout metadata_t meta,
        in    pna_main_parser_input_metadata_t istd)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.enc_ip);
        transition select(hdr.enc_ip.protocol) {
            IP_PROTO_UDP: parse_enc_udp;
            default: reject;
        }
    }

    state parse_enc_udp {
        pkt.extract(hdr.enc_udp);
        transition parse_psp;
    }

    state parse_psp {
        pkt.extract(hdr.psp);
        transition select(hdr.psp.virtCookie) {
            VIRT_COOKIE: parse_virt_cookie;
            default: accept;
        }
    }

    state parse_virt_cookie {
        pkt.extract(hdr.pspvc);
        transition accept;
    }
}
