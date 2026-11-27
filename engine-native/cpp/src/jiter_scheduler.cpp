#include "jiter_scheduler.hpp"

#include <algorithm>
#include <cstring>

namespace jiter {

TrafficScheduler::TrafficScheduler(
    PacketPool& pool,
    size_t max_game_pkts,
    size_t max_stream_pkts,
    size_t max_bg_pkts
)
    : pool_(pool),
      max_game_pkts_(max_game_pkts),
      max_stream_pkts_(max_stream_pkts),
      max_bg_pkts_(max_bg_pkts) {}

TrafficScheduler::~TrafficScheduler() {
    clear();
}

void TrafficScheduler::configure_pacer(double bg_pacer_ratio, double estimated_link_mbps) {
    std::lock_guard<std::mutex> lock(mu_);
    bg_pacer_ratio_ = std::clamp(bg_pacer_ratio, 0.15, 1.0);
    if (estimated_link_mbps > 0.1) {
        link_bytes_per_ms_ = (estimated_link_mbps * 1e6 / 8.0) / 1000.0;
    }
}

bool TrafficScheduler::enqueue(
    const uint8_t* raw_packet,
    size_t len,
    int64_t now_ms,
    int tier_override
) {
    if (raw_packet == nullptr || len == 0 || len > kMaxPacketBytes) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.dropped_invalid;
        return false;
    }

    JiterPacketMeta meta{};
    if (!jiter_parse_ipv4_packet(raw_packet, len, &meta)) {
        std::lock_guard<std::mutex> lock(mu_);
        ++stats_.dropped_invalid;
        return false;
    }

    uint8_t tier = meta.traffic_tier;
    if (tier_override == static_cast<int>(JITER_TIER_GAME) ||
        tier_override == static_cast<int>(JITER_TIER_STREAMING) ||
        tier_override == static_cast<int>(JITER_TIER_BACKGROUND)) {
        tier = static_cast<uint8_t>(tier_override);
        meta.traffic_tier = tier;
    }

    std::lock_guard<std::mutex> lock(mu_);

    std::deque<PacketSlot*>* target_q = nullptr;
    size_t max_depth = 0;
    if (tier == JITER_TIER_GAME) {
        target_q = &q_game_;
        max_depth = max_game_pkts_;
    } else if (tier == JITER_TIER_STREAMING) {
        target_q = &q_stream_;
        max_depth = max_stream_pkts_;
    } else {
        target_q = &q_bg_;
        max_depth = max_bg_pkts_;
    }

    if (target_q->size() >= max_depth) {
        ++stats_.dropped_queue_full;
        return false;
    }

    PacketSlot* slot = pool_.acquire();
    if (slot == nullptr) {
        ++stats_.dropped_queue_full;
        return false;
    }

    std::memcpy(slot->data, raw_packet, len);
    slot->len = len;
    slot->meta = meta;
    slot->enqueue_ts_ms = now_ms;
    target_q->push_back(slot);

    if (tier == JITER_TIER_GAME) {
        ++stats_.enqueued_game;
    } else if (tier == JITER_TIER_STREAMING) {
        ++stats_.enqueued_streaming;
    } else {
        ++stats_.enqueued_background;
    }
    return true;
}

void TrafficScheduler::refill_bg_tokens_locked(int64_t now_ms) {
    if (last_token_ms_ < 0) {
        last_token_ms_ = now_ms;
        return;
    }
    if (now_ms <= last_token_ms_) {
        return;
    }
    const double dt_ms = static_cast<double>(now_ms - last_token_ms_);
    last_token_ms_ = now_ms;

    const double refill_bytes = dt_ms * link_bytes_per_ms_ * bg_pacer_ratio_;
    const double max_burst_bytes = std::max(3072.0, link_bytes_per_ms_ * 10.0 * bg_pacer_ratio_);
    bg_tokens_bytes_ = std::min(max_burst_bytes, bg_tokens_bytes_ + refill_bytes);
}

PacketSlot* TrafficScheduler::dequeue(int64_t now_ms) {
    std::lock_guard<std::mutex> lock(mu_);
    refill_bg_tokens_locked(now_ms);

    // 1. Strict Priority: GAME always goes first (zero pacer throttle)
    if (!q_game_.empty()) {
        PacketSlot* slot = q_game_.front();
        q_game_.pop_front();
        ++stats_.dequeued_game;
        return slot;
    }

    // 2. STREAMING served immediately after GAME
    if (!q_stream_.empty()) {
        PacketSlot* slot = q_stream_.front();
        q_stream_.pop_front();
        ++stats_.dequeued_streaming;
        return slot;
    }

    // 3. BACKGROUND governed by anti-bufferbloat token bucket
    if (!q_bg_.empty()) {
        PacketSlot* front = q_bg_.front();
        if (bg_pacer_ratio_ >= 0.99 || bg_tokens_bytes_ >= static_cast<double>(front->len)) {
            if (bg_pacer_ratio_ < 0.99) {
                bg_tokens_bytes_ -= static_cast<double>(front->len);
            }
            q_bg_.pop_front();
            ++stats_.dequeued_background;
            return front;
        }
        ++stats_.bg_pacer_deferrals;
    }

    return nullptr;
}

void TrafficScheduler::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    for (PacketSlot* s : q_game_) pool_.release(s);
    for (PacketSlot* s : q_stream_) pool_.release(s);
    for (PacketSlot* s : q_bg_) pool_.release(s);
    q_game_.clear();
    q_stream_.clear();
    q_bg_.clear();
    last_token_ms_ = -1;
}

SchedulerStats TrafficScheduler::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    SchedulerStats copy = stats_;
    copy.depth_game = q_game_.size();
    copy.depth_streaming = q_stream_.size();
    copy.depth_background = q_bg_.size();
    return copy;
}

} // namespace jiter
