#ifndef JITER_PACKET_H
#define JITER_PACKET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JITER_PROTO_ICMP 1u
#define JITER_PROTO_TCP  6u
#define JITER_PROTO_UDP  17u

#define JITER_TIER_GAME       0u
#define JITER_TIER_STREAMING  1u
#define JITER_TIER_BACKGROUND 2u

#define JITER_FEC_HEADER_BYTES 8u

typedef struct {
    uint8_t ip_version;
    uint8_t protocol;
    uint8_t dscp;
    uint8_t traffic_tier;
    uint16_t header_len;
    uint16_t total_len;
    uint16_t payload_len;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t src_ip;
    uint32_t dst_ip;
} JiterPacketMeta;

typedef struct {
    uint32_t group_id;
    uint16_t payload_len;
    uint8_t slot_index;
    uint8_t block_k;
    uint8_t is_parity;
} JiterFecHeader;

/* Zero-allocation IPv4 + TCP/UDP header parser & traffic-tier classifier.
 * Returns 1 if valid IPv4 packet, 0 otherwise. */
int jiter_parse_ipv4_packet(const uint8_t* raw, size_t len, JiterPacketMeta* out_meta);

/* Pack / unpack 8-byte JITER XOR FEC wire header (big-endian).
 * Returns 1 on success, 0 on invalid arguments/bounds. */
int jiter_fec_pack_header(const JiterFecHeader* hdr, uint8_t* out_buf, size_t buf_len);
int jiter_fec_unpack_header(const uint8_t* buf, size_t buf_len, JiterFecHeader* out_hdr);

/* Word-aligned (64-bit stride, UB-free) GF(2) bitwise XOR accumulator:
 * dst[i] ^= src[i] for i in 0..len */
void jiter_xor_accumulate(uint8_t* dst, const uint8_t* src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* JITER_PACKET_H */
