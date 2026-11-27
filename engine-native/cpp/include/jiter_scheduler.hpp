#ifndef JITER_SCHEDULER_HPP
#define JITER_SCHEDULER_HPP

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

#include "jiter_packet.h"
#include "jiter_packet_pool.hpp"

namespace jiter {

struct SchedulerStats {
    uint64_t enqueued_game = 0;
    uint64_t enqueued_streaming = 0;
    uint64_t enqueued_background = 0;
    uint64_t dropped_queue_full = 0;
    uint64_t dropped_invalid = 0;
    uint64_t dequeued_game = 0;
    uint64_t dequeued_streaming = 0;
    uint64_t dequeued_background = 0;
    uint64_t bg_pacer_deferrals = 0;
    size_t depth_game = 0;
    size_t depth_streaming = 0;
    size_t depth_background = 0;
};

/**
 * 3-tier Strict Priority Traffic Scheduler + Anti-Bufferbloat Background Token-Bucket Pacer.
 *
 * Priority order:
 *   1. GAME       (strict VIP, never throttled by background pacer)
 *   2. STREAMING  (bounded queue depth to keep 1080p smooth without bloat)
 *   3. BACKGROUND (token-bucket paced via `bg_pacer_ratio` from Rust AdaptiveController)
 */
class TrafficScheduler {
public:
    explicit TrafficScheduler(
        PacketPool& pool,
        size_t max_game_pkts = 64,
        size_t max_stream_pkts = 64,
        size_t max_bg_pkts = 48
    );
    ~TrafficScheduler();

    TrafficScheduler(const TrafficScheduler&) = delete;
    TrafficScheduler& operator=(const TrafficScheduler&) = delete;

    /* Adjust background pacing dynamically without restarting the tunnel.
     * `ratio` in [0.15, 1.0]; `link_mbps` > 0. */
    void configure_pacer(double bg_pacer_ratio, double estimated_link_mbps);

    /* Parse raw IPv4 packet via C layer, copy into PacketPool slot, and enqueue.
     * Pass `tier_override >= 0` to override heuristic tier using Android UID profile. */
    bool enqueue(const uint8_t* raw_packet, size_t len, int64_t now_ms, int tier_override = -1);

    /* Pop highest-priority eligible packet slot. Caller MUST call `pool.release(slot)`. */
    PacketSlot* dequeue(int64_t now_ms);

    /* Drain and release all queued slots safely back to PacketPool (called on STOP). */
    void clear();

    SchedulerStats stats() const;

private:
    void refill_bg_tokens_locked(int64_t now_ms);

    PacketPool& pool_;
    const size_t max_game_pkts_;
    const size_t max_stream_pkts_;
    const size_t max_bg_pkts_;

    mutable std::mutex mu_;
    std::deque<PacketSlot*> q_game_;
    std::deque<PacketSlot*> q_stream_;
    std::deque<PacketSlot*> q_bg_;

    double bg_pacer_ratio_ = 1.0;
    double link_bytes_per_ms_ = 3125.0; // default ~25 Mbps
    double bg_tokens_bytes_ = 4096.0;
    int64_t last_token_ms_ = -1;

    SchedulerStats stats_{};
};

} // namespace jiter

#endif // JITER_SCHEDULER_HPP
