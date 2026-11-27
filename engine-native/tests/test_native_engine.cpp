#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "jiter_packet.h"
#include "jiter_packet_pool.hpp"
#include "jiter_scheduler.hpp"

static std::vector<uint8_t> make_ipv4_udp(uint16_t src_port, uint16_t dst_port, size_t payload_len) {
    const size_t total = 20 + 8 + payload_len;
    std::vector<uint8_t> pkt(total, 0);
    pkt[0] = 0x45; // IPv4, IHL=5 (20 bytes)
    pkt[2] = static_cast<uint8_t>((total >> 8) & 0xFF);
    pkt[3] = static_cast<uint8_t>(total & 0xFF);
    pkt[9] = JITER_PROTO_UDP;
    // src 10.77.0.2 -> dst 1.1.1.1
    pkt[12] = 10; pkt[13] = 77; pkt[14] = 0; pkt[15] = 2;
    pkt[16] = 1;  pkt[17] = 1;  pkt[18] = 1; pkt[19] = 1;
    // UDP header
    pkt[20] = static_cast<uint8_t>((src_port >> 8) & 0xFF);
    pkt[21] = static_cast<uint8_t>(src_port & 0xFF);
    pkt[22] = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
    pkt[23] = static_cast<uint8_t>(dst_port & 0xFF);
    const uint16_t udp_len = static_cast<uint16_t>(8 + payload_len);
    pkt[24] = static_cast<uint8_t>((udp_len >> 8) & 0xFF);
    pkt[25] = static_cast<uint8_t>(udp_len & 0xFF);
    for (size_t i = 0; i < payload_len; ++i) {
        pkt[28 + i] = static_cast<uint8_t>((i * 37 + 11) & 0xFF);
    }
    return pkt;
}

static std::vector<uint8_t> make_ipv4_tcp(uint16_t src_port, uint16_t dst_port, size_t payload_len) {
    const size_t total = 20 + 20 + payload_len;
    std::vector<uint8_t> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<uint8_t>((total >> 8) & 0xFF);
    pkt[3] = static_cast<uint8_t>(total & 0xFF);
    pkt[9] = JITER_PROTO_TCP;
    pkt[12] = 10; pkt[13] = 77; pkt[14] = 0; pkt[15] = 2;
    pkt[16] = 8;  pkt[17] = 8;  pkt[18] = 8; pkt[19] = 8;
    pkt[20] = static_cast<uint8_t>((src_port >> 8) & 0xFF);
    pkt[21] = static_cast<uint8_t>(src_port & 0xFF);
    pkt[22] = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
    pkt[23] = static_cast<uint8_t>(dst_port & 0xFF);
    pkt[32] = 0x50; // TCP data offset = 5 (20 bytes)
    return pkt;
}

static void test_c_packet_parser_and_fec_header() {
    auto game_udp = make_ipv4_udp(51000, 30001, 80); // 108 bytes total -> GAME
    JiterPacketMeta meta{};
    assert(jiter_parse_ipv4_packet(game_udp.data(), game_udp.size(), &meta) == 1);
    assert(meta.ip_version == 4);
    assert(meta.protocol == JITER_PROTO_UDP);
    assert(meta.src_port == 51000);
    assert(meta.dst_port == 30001);
    assert(meta.header_len == 28);
    assert(meta.payload_len == 80);
    assert(meta.traffic_tier == JITER_TIER_GAME);

    auto stream_udp = make_ipv4_udp(51001, 443, 1200); // large UDP QUIC -> STREAMING
    assert(jiter_parse_ipv4_packet(stream_udp.data(), stream_udp.size(), &meta) == 1);
    assert(meta.traffic_tier == JITER_TIER_STREAMING);

    auto bg_tcp = make_ipv4_tcp(51002, 8080, 1300); // bulk TCP non-443 -> BACKGROUND
    assert(jiter_parse_ipv4_packet(bg_tcp.data(), bg_tcp.size(), &meta) == 1);
    assert(meta.protocol == JITER_PROTO_TCP);
    assert(meta.traffic_tier == JITER_TIER_BACKGROUND);

    // Reject truncated / bad IP version
    uint8_t bad[10] = {0x60};
    assert(jiter_parse_ipv4_packet(bad, sizeof(bad), &meta) == 0);

    // 8-byte FEC header round-trip
    JiterFecHeader h_in{0x12345678u, 1180u, 2u, 4u, 1u};
    uint8_t wire[JITER_FEC_HEADER_BYTES]{};
    assert(jiter_fec_pack_header(&h_in, wire, sizeof(wire)) == 1);
    JiterFecHeader h_out{};
    assert(jiter_fec_unpack_header(wire, sizeof(wire), &h_out) == 1);
    assert(h_out.group_id == h_in.group_id);
    assert(h_out.payload_len == h_in.payload_len);
    assert(h_out.slot_index == h_in.slot_index);
    assert(h_out.block_k == h_in.block_k);
    assert(h_out.is_parity == h_in.is_parity);

    // 64-bit aligned XOR GF(2) recovery test (unaligned tail length = 73 bytes)
    uint8_t p1[73], p2[73], p3[73], parity[73], recovered[73];
    for (size_t i = 0; i < sizeof(p1); ++i) {
        p1[i] = static_cast<uint8_t>(i ^ 0xA5);
        p2[i] = static_cast<uint8_t>((i * 3) + 7);
        p3[i] = static_cast<uint8_t>(255 - i);
    }
    std::memset(parity, 0, sizeof(parity));
    jiter_xor_accumulate(parity, p1, sizeof(p1));
    jiter_xor_accumulate(parity, p2, sizeof(p2));
    jiter_xor_accumulate(parity, p3, sizeof(p3));

    // Lose p2 -> recover p2 = p1 ^ p3 ^ parity
    std::memset(recovered, 0, sizeof(recovered));
    jiter_xor_accumulate(recovered, p1, sizeof(p1));
    jiter_xor_accumulate(recovered, p3, sizeof(p3));
    jiter_xor_accumulate(recovered, parity, sizeof(parity));
    assert(std::memcmp(recovered, p2, sizeof(p2)) == 0);

    std::printf("[PASS] C packet parser, FEC header framing, and 64-bit GF(2) XOR kernel\n");
}

static void test_c_relay_wire_header_golden_vector() {
    // Golden interop vector matching docs/architecture/relay-wire-protocol.md
    JiterWireHeader h_in{};
    h_in.version = JITER_WIRE_VERSION;
    h_in.msg_type = JITER_MSG_DATA_FEC;
    h_in.traffic_tier = JITER_TIER_GAME;
    h_in.flags = JITER_FLAG_FEC_PARITY;
    h_in.session_id = 0x11223344u;
    h_in.sequence = 42u;
    h_in.payload_len = 128u;
    h_in.pacer_q8 = jiter_pacer_ratio_to_q8(0.35);
    h_in.fec_mode = 2u; // XOR_K2

    uint8_t wire[JITER_WIRE_HEADER_BYTES]{};
    assert(jiter_wire_pack_header(&h_in, wire, sizeof(wire)) == 1);

    const uint8_t expected[JITER_WIRE_HEADER_BYTES] = {
        0x4Au, 0x54u, 0x16u, 0x02u,
        0x11u, 0x22u, 0x33u, 0x44u,
        0x00u, 0x00u, 0x00u, 0x2Au,
        0x00u, 0x80u, 0x59u, 0x02u,
    };
    assert(std::memcmp(wire, expected, sizeof(expected)) == 0);

    JiterWireHeader h_out{};
    assert(jiter_wire_unpack_header(wire, sizeof(wire), &h_out) == 1);
    assert(h_out.version == h_in.version);
    assert(h_out.msg_type == h_in.msg_type);
    assert(h_out.traffic_tier == h_in.traffic_tier);
    assert(h_out.flags == h_in.flags);
    assert(h_out.session_id == h_in.session_id);
    assert(h_out.sequence == h_in.sequence);
    assert(h_out.payload_len == h_in.payload_len);
    assert(h_out.pacer_q8 == 0x59u);
    assert(h_out.fec_mode == 2u);

    // Reject wrong magic & wrong version
    uint8_t bad_magic[JITER_WIRE_HEADER_BYTES];
    std::memcpy(bad_magic, wire, sizeof(wire));
    bad_magic[0] = 0x00u;
    assert(jiter_wire_unpack_header(bad_magic, sizeof(bad_magic), &h_out) == 0);

    uint8_t bad_ver[JITER_WIRE_HEADER_BYTES];
    std::memcpy(bad_ver, wire, sizeof(wire));
    bad_ver[2] = 0x26u; // version 2
    assert(jiter_wire_unpack_header(bad_ver, sizeof(bad_ver), &h_out) == 0);

    // Pacer Q8 clamp & round-trip checks
    assert(jiter_pacer_ratio_to_q8(-0.5) == 0u);
    assert(jiter_pacer_ratio_to_q8(1.5) == 255u);
    assert(jiter_pacer_q8_to_ratio(255u) == 1.0);

    std::printf("[PASS] C 16-byte JITER Relay Wire Protocol v1 codec & golden vector\n");
}

static void test_cpp_packet_pool_and_scheduler() {
    jiter::PacketPool pool(8);
    std::vector<jiter::PacketSlot*> held;
    for (int i = 0; i < 8; ++i) {
        auto* s = pool.acquire();
        assert(s != nullptr);
        held.push_back(s);
    }
    // Exhausted -> returns nullptr cleanly without malloc/crash
    assert(pool.acquire() == nullptr);
    assert(pool.stats().exhausted_drops == 1);
    for (auto* s : held) pool.release(s);
    assert(pool.stats().in_use == 0);

    // Strict Priority Queue + Anti-Bufferbloat Background Pacer test
    jiter::TrafficScheduler sched(pool, 4, 4, 4);
    sched.configure_pacer(0.20, 10.0); // Throttle background heavily (2 Mbps = 250 B/ms)

    auto bg = make_ipv4_tcp(40000, 9000, 1300);      // BACKGROUND (1340B)
    auto st = make_ipv4_udp(40001, 443, 1200);       // STREAMING (1228B)
    auto gm = make_ipv4_udp(40002, 30001, 80);       // GAME (108B)

    // Enqueue BACKGROUND first, then STREAMING, then GAME!
    assert(sched.enqueue(bg.data(), bg.size(), 1000));
    assert(sched.enqueue(bg.data(), bg.size(), 1000));
    assert(sched.enqueue(bg.data(), bg.size(), 1000));
    assert(sched.enqueue(bg.data(), bg.size(), 1000));
    assert(sched.enqueue(st.data(), st.size(), 1000));
    assert(sched.enqueue(gm.data(), gm.size(), 1000));

    // Dequeue order MUST be GAME first, then STREAMING, despite BACKGROUND arriving earlier!
    auto* first = sched.dequeue(1000);
    assert(first != nullptr && first->meta.traffic_tier == JITER_TIER_GAME);
    pool.release(first);

    auto* second = sched.dequeue(1000);
    assert(second != nullptr && second->meta.traffic_tier == JITER_TIER_STREAMING);
    pool.release(second);

    // Background drains until initial burst tokens run out, then pacer defers!
    int bg_popped = 0;
    while (auto* s = sched.dequeue(1000)) {
        assert(s->meta.traffic_tier == JITER_TIER_BACKGROUND);
        pool.release(s);
        ++bg_popped;
    }
    assert(bg_popped < 4);
    assert(sched.stats().bg_pacer_deferrals >= 1);

    // After 20ms elapses, tokens refill -> remaining background packets release!
    auto* later = sched.dequeue(1020);
    assert(later != nullptr && later->meta.traffic_tier == JITER_TIER_BACKGROUND);
    pool.release(later);

    sched.clear();
    assert(pool.stats().in_use == 0);
    std::printf("[PASS] C++ slab PacketPool and 3-tier Strict Priority Scheduler + BG Pacer\n");
}

int main() {
    test_c_packet_parser_and_fec_header();
    test_c_relay_wire_header_golden_vector();
    test_cpp_packet_pool_and_scheduler();
    std::printf("ALL NATIVE C/C++ ENGINE TESTS PASSED!\n");
    return 0;
}
