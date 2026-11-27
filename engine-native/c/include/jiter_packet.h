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

#define JITER_FEC_HEADER_BYTES  8u
#define JITER_WIRE_HEADER_BYTES 16u
#define JITER_WIRE_MAGIC_0      0x4Au /* 'J' */
#define JITER_WIRE_MAGIC_1      0x54u /* 'T' */
#define JITER_WIRE_VERSION      1u

#define JITER_MSG_PROBE_REQ     1u
#define JITER_MSG_PROBE_RESP    2u
#define JITER_MSG_HELLO_REQ     3u
#define JITER_MSG_HELLO_ACK     4u
#define JITER_MSG_DATA_PLAIN    5u
#define JITER_MSG_DATA_FEC      6u
#define JITER_MSG_POLICY_SYNC   7u
#define JITER_MSG_CONTROL       8u

#define JITER_FLAG_GOODBYE      0x01u
#define JITER_FLAG_FEC_PARITY   0x02u
#define JITER_FLAG_ENCRYPTED    0x04u

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

typedef struct {
    uint8_t version;
    uint8_t msg_type;
    uint8_t traffic_tier;
    uint8_t flags;
    uint32_t session_id;
    uint32_t sequence;
    uint16_t payload_len;
    uint8_t pacer_q8;
    uint8_t fec_mode;
} JiterWireHeader;

/* Zero-allocation IPv4 + TCP/UDP header parser & traffic-tier classifier.
 * Returns 1 if valid IPv4 packet, 0 otherwise. */
int jiter_parse_ipv4_packet(const uint8_t* raw, size_t len, JiterPacketMeta* out_meta);

/* Pack / unpack 8-byte JITER XOR FEC wire header (big-endian).
 * Returns 1 on success, 0 on invalid arguments/bounds. */
int jiter_fec_pack_header(const JiterFecHeader* hdr, uint8_t* out_buf, size_t buf_len);
int jiter_fec_unpack_header(const uint8_t* buf, size_t buf_len, JiterFecHeader* out_hdr);

/* Pack / unpack 16-byte JITER Relay Wire Protocol v1 header (big-endian).
 * Returns 1 on success, 0 on invalid magic/version/bounds. */
int jiter_wire_pack_header(const JiterWireHeader* hdr, uint8_t* out_buf, size_t buf_len);
int jiter_wire_unpack_header(const uint8_t* buf, size_t buf_len, JiterWireHeader* out_hdr);

/* Convert bg_pacer_ratio [0.0..1.0] <-> wire Q8 byte [0..255]. */
uint8_t jiter_pacer_ratio_to_q8(double ratio);
double jiter_pacer_q8_to_ratio(uint8_t q8);

/* Word-aligned (64-bit stride, UB-free) GF(2) bitwise XOR accumulator:
 * dst[i] ^= src[i] for i in 0..len */
void jiter_xor_accumulate(uint8_t* dst, const uint8_t* src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* JITER_PACKET_H */
