#include "jiter_packet.h"

#include <string.h>

static uint16_t read_be16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

static uint8_t classify_packet_tier(uint8_t proto, uint8_t dscp, uint16_t total_len,
                                    uint16_t dst_port) {
    /* DSCP EF (46) or CS4 (32) explicitly marks real-time game/voice traffic */
    if (dscp == 46u || dscp == 32u) {
        return JITER_TIER_GAME;
    }
    /* ICMP echo probes and small UDP game/VoIP datagrams get VIP priority */
    if (proto == JITER_PROTO_ICMP) {
        return JITER_TIER_GAME;
    }
    if (proto == JITER_PROTO_UDP) {
        if (total_len <= 320u && dst_port != 53u) {
            return JITER_TIER_GAME;
        }
        /* DNS (53) should never stall behind bulk downloads either */
        if (dst_port == 53u) {
            return JITER_TIER_GAME;
        }
        /* Larger UDP (e.g., QUIC/HTTP3 video streaming on 443) */
        return JITER_TIER_STREAMING;
    }
    if (proto == JITER_PROTO_TCP) {
        /* Small TCP ACK / control packets get priority to keep downloads & streams responsive */
        if (total_len <= 96u) {
            return JITER_TIER_GAME;
        }
        if (dst_port == 443u || dst_port == 80u) {
            return JITER_TIER_STREAMING;
        }
    }
    return JITER_TIER_BACKGROUND;
}

int jiter_parse_ipv4_packet(const uint8_t* raw, size_t len, JiterPacketMeta* out_meta) {
    if (raw == NULL || out_meta == NULL || len < 20u) {
        return 0;
    }

    uint8_t version = (uint8_t)(raw[0] >> 4);
    uint8_t ihl = (uint8_t)(raw[0] & 0x0Fu);
    uint16_t ip_header_len = (uint16_t)(ihl * 4u);
    if (version != 4u || ip_header_len < 20u || (size_t)ip_header_len > len) {
        return 0;
    }

    uint16_t total_len = read_be16(raw + 2);
    if (total_len < ip_header_len || (size_t)total_len > len) {
        return 0;
    }

    uint8_t dscp = (uint8_t)(raw[1] >> 2);
    uint8_t proto = raw[9];
    uint32_t src_ip = read_be32(raw + 12);
    uint32_t dst_ip = read_be32(raw + 16);

    uint16_t src_port = 0u;
    uint16_t dst_port = 0u;
    uint16_t transport_hdr_len = 0u;

    if (proto == JITER_PROTO_UDP) {
        if ((size_t)ip_header_len + 8u <= (size_t)total_len) {
            src_port = read_be16(raw + ip_header_len);
            dst_port = read_be16(raw + ip_header_len + 2);
            transport_hdr_len = 8u;
        }
    } else if (proto == JITER_PROTO_TCP) {
        if ((size_t)ip_header_len + 20u <= (size_t)total_len) {
            src_port = read_be16(raw + ip_header_len);
            dst_port = read_be16(raw + ip_header_len + 2);
            uint8_t data_offset = (uint8_t)(raw[ip_header_len + 12] >> 4);
            uint16_t tcp_len = (uint16_t)(data_offset * 4u);
            if (tcp_len >= 20u && (size_t)ip_header_len + tcp_len <= (size_t)total_len) {
                transport_hdr_len = tcp_len;
            }
        }
    }

    uint16_t combined_hdr = (uint16_t)(ip_header_len + transport_hdr_len);
    uint16_t payload_len = (total_len >= combined_hdr) ? (uint16_t)(total_len - combined_hdr) : 0u;

    out_meta->ip_version = version;
    out_meta->protocol = proto;
    out_meta->dscp = dscp;
    out_meta->traffic_tier = classify_packet_tier(proto, dscp, total_len, dst_port);
    out_meta->header_len = combined_hdr;
    out_meta->total_len = total_len;
    out_meta->payload_len = payload_len;
    out_meta->src_port = src_port;
    out_meta->dst_port = dst_port;
    out_meta->src_ip = src_ip;
    out_meta->dst_ip = dst_ip;
    return 1;
}

int jiter_fec_pack_header(const JiterFecHeader* hdr, uint8_t* out_buf, size_t buf_len) {
    if (hdr == NULL || out_buf == NULL || buf_len < JITER_FEC_HEADER_BYTES) {
        return 0;
    }
    if (hdr->block_k < 1u || hdr->block_k > 15u) {
        return 0;
    }

    out_buf[0] = (uint8_t)((hdr->group_id >> 24) & 0xFFu);
    out_buf[1] = (uint8_t)((hdr->group_id >> 16) & 0xFFu);
    out_buf[2] = (uint8_t)((hdr->group_id >> 8) & 0xFFu);
    out_buf[3] = (uint8_t)(hdr->group_id & 0xFFu);
    out_buf[4] = (uint8_t)((hdr->payload_len >> 8) & 0xFFu);
    out_buf[5] = (uint8_t)(hdr->payload_len & 0xFFu);
    out_buf[6] = hdr->slot_index;
    out_buf[7] = (uint8_t)((hdr->is_parity ? 0x80u : 0x00u) | (hdr->block_k & 0x0Fu));
    return 1;
}

int jiter_fec_unpack_header(const uint8_t* buf, size_t buf_len, JiterFecHeader* out_hdr) {
    if (buf == NULL || out_hdr == NULL || buf_len < JITER_FEC_HEADER_BYTES) {
        return 0;
    }
    uint8_t block_k = (uint8_t)(buf[7] & 0x0Fu);
    if (block_k < 1u || block_k > 15u) {
        return 0;
    }

    out_hdr->group_id = read_be32(buf);
    out_hdr->payload_len = read_be16(buf + 4);
    out_hdr->slot_index = buf[6];
    out_hdr->block_k = block_k;
    out_hdr->is_parity = (uint8_t)((buf[7] & 0x80u) != 0u ? 1u : 0u);
    return 1;
}

void jiter_xor_accumulate(uint8_t* dst, const uint8_t* src, size_t len) {
    if (dst == NULL || src == NULL || len == 0u) {
        return;
    }
    size_t i = 0u;
    /* Process 8 bytes per loop via memcpy (strict-aliasing & unaligned-safe; compiles to 64-bit XOR) */
    for (; i + sizeof(uint64_t) <= len; i += sizeof(uint64_t)) {
        uint64_t a = 0u;
        uint64_t b = 0u;
        memcpy(&a, dst + i, sizeof(uint64_t));
        memcpy(&b, src + i, sizeof(uint64_t));
        a ^= b;
        memcpy(dst + i, &a, sizeof(uint64_t));
    }
    for (; i < len; ++i) {
        dst[i] ^= src[i];
    }
}
