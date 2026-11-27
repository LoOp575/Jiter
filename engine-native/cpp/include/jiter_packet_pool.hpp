#ifndef JITER_PACKET_POOL_HPP
#define JITER_PACKET_POOL_HPP

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include "jiter_packet.h"

namespace jiter {

constexpr size_t kMaxPacketBytes = 1536;

struct PacketSlot {
    alignas(8) uint8_t data[kMaxPacketBytes]{};
    size_t len = 0;
    uint32_t pool_index = 0;
    int64_t enqueue_ts_ms = 0;
    JiterPacketMeta meta{};
};

struct PoolStats {
    size_t capacity = 0;
    size_t in_use = 0;
    size_t peak_in_use = 0;
    uint64_t total_acquires = 0;
    uint64_t exhausted_drops = 0;
};

/**
 * Fixed-capacity slab memory pool for network packets.
 *
 * Pre-allocates all MTU buffers once during construction so the packet hot path
 * executes zero dynamic heap allocations (zero malloc/new, zero fragmentation,
 * predictable RAM PSS footprint: 256 slots * 1536B ~= 384 KB).
 */
class PacketPool {
public:
    explicit PacketPool(size_t capacity = 256)
        : slots_(capacity), free_indices_(capacity), capacity_(capacity) {
        for (size_t i = 0; i < capacity; ++i) {
            slots_[i].pool_index = static_cast<uint32_t>(i);
            free_indices_[i] = static_cast<uint32_t>(capacity - 1 - i);
        }
    }

    PacketPool(const PacketPool&) = delete;
    PacketPool& operator=(const PacketPool&) = delete;

    PacketSlot* acquire() {
        std::lock_guard<std::mutex> lock(mu_);
        if (free_indices_.empty()) {
            ++exhausted_drops_;
            return nullptr;
        }
        uint32_t idx = free_indices_.back();
        free_indices_.pop_back();
        ++in_use_;
        ++total_acquires_;
        if (in_use_ > peak_in_use_) {
            peak_in_use_ = in_use_;
        }
        PacketSlot* slot = &slots_[idx];
        slot->len = 0;
        slot->enqueue_ts_ms = 0;
        return slot;
    }

    void release(PacketSlot* slot) {
        if (slot == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (slot->pool_index >= capacity_) {
            return;
        }
        slot->len = 0;
        free_indices_.push_back(slot->pool_index);
        if (in_use_ > 0) {
            --in_use_;
        }
    }

    PoolStats stats() const {
        std::lock_guard<std::mutex> lock(mu_);
        return PoolStats{
            capacity_,
            in_use_,
            peak_in_use_,
            total_acquires_,
            exhausted_drops_,
        };
    }

private:
    mutable std::mutex mu_;
    std::vector<PacketSlot> slots_;
    std::vector<uint32_t> free_indices_;
    size_t capacity_ = 0;
    size_t in_use_ = 0;
    size_t peak_in_use_ = 0;
    uint64_t total_acquires_ = 0;
    uint64_t exhausted_drops_ = 0;
};

} // namespace jiter

#endif // JITER_PACKET_POOL_HPP
