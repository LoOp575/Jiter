#include <jni.h>

#include <cstdint>
#include <memory>

#include "jiter_packet.h"
#include "jiter_packet_pool.hpp"
#include "jiter_scheduler.hpp"

#if JITER_HAS_RUST_MATH
#include "jiter_math_ffi.h"
#endif

namespace {

constexpr jint kCapCPacketEngine = 1 << 0;
constexpr jint kCapCppMemoryScheduler = 1 << 1;
constexpr jint kCapRustMathEngine = 1 << 2;

struct NativeSessionContext {
    jiter::PacketPool pool{256};
    jiter::TrafficScheduler scheduler{pool, 64, 64, 48};
#if JITER_HAS_RUST_MATH
    JiterEngineHandle* rust_engine = nullptr;
#endif

    NativeSessionContext() {
#if JITER_HAS_RUST_MATH
        rust_engine = jiter_engine_create();
#endif
    }

    ~NativeSessionContext() {
        scheduler.clear();
#if JITER_HAS_RUST_MATH
        if (rust_engine != nullptr) {
            jiter_engine_destroy(rust_engine);
            rust_engine = nullptr;
        }
#endif
    }
};

NativeSessionContext* from_handle(jlong ptr) {
    if (ptr == 0) {
        return nullptr;
    }
    return reinterpret_cast<NativeSessionContext*>(static_cast<uintptr_t>(ptr));
}

} // namespace

extern "C" {

JNIEXPORT jint JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeCapabilities(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
    jint caps = kCapCPacketEngine | kCapCppMemoryScheduler;
#if JITER_HAS_RUST_MATH
    if (jiter_engine_abi_version() == JITER_ENGINE_ABI_VERSION) {
        caps |= kCapRustMathEngine;
    }
#endif
    return caps;
}

JNIEXPORT jlong JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeCreateSession(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
    auto* ctx = new (std::nothrow) NativeSessionContext();
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(ctx));
}

JNIEXPORT void JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeDestroySession(
    JNIEnv* env,
    jobject thiz,
    jlong handle
) {
    (void)env;
    (void)thiz;
    auto* ctx = from_handle(handle);
    delete ctx;
}

JNIEXPORT void JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeResetSession(
    JNIEnv* env,
    jobject thiz,
    jlong handle
) {
    (void)env;
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr) return;
    ctx->scheduler.clear();
#if JITER_HAS_RUST_MATH
    if (ctx->rust_engine != nullptr) {
        jiter_engine_reset(ctx->rust_engine);
    }
#endif
}

JNIEXPORT void JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeResetBaseline(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jdouble new_min_rtt_ms
) {
    (void)env;
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr) return;
#if JITER_HAS_RUST_MATH
    if (ctx->rust_engine != nullptr) {
        jiter_engine_reset_baseline(ctx->rust_engine, static_cast<double>(new_min_rtt_ms));
    }
#else
    (void)new_min_rtt_ms;
#endif
}

JNIEXPORT jboolean JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeSubmitRtt(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jdouble rtt_ms,
    jlong timestamp_ms
) {
    (void)env;
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr) return JNI_FALSE;
#if JITER_HAS_RUST_MATH
    if (ctx->rust_engine == nullptr) return JNI_FALSE;
    return jiter_engine_submit_rtt(
        ctx->rust_engine,
        static_cast<double>(rtt_ms),
        static_cast<int64_t>(timestamp_ms)
    ) != 0 ? JNI_TRUE : JNI_FALSE;
#else
    (void)rtt_ms;
    (void)timestamp_ms;
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeStepMath(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong now_ms,
    jint profile_id,
    jdouble loss_pct,
    jdouble bandwidth_mbps,
    jboolean has_alt_route,
    jdouble alt_srtt_ms,
    jdouble alt_jitter_ms,
    jdouble alt_loss_pct,
    jdouble alt_bloat_ms,
    jdoubleArray out_doubles,
    jintArray out_ints
) {
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr || out_doubles == nullptr || out_ints == nullptr) {
        return JNI_FALSE;
    }
    if (env->GetArrayLength(out_doubles) < 7 || env->GetArrayLength(out_ints) < 6) {
        return JNI_FALSE;
    }

#if JITER_HAS_RUST_MATH
    if (ctx->rust_engine == nullptr) {
        return JNI_FALSE;
    }

    JiterStepInput input{};
    input.now_ms = static_cast<int64_t>(now_ms);
    input.profile_id = static_cast<uint32_t>(profile_id);
    input.loss_pct = static_cast<double>(loss_pct);
    input.bandwidth_mbps = static_cast<double>(bandwidth_mbps);
    input.has_alt_route = has_alt_route == JNI_TRUE ? 1u : 0u;
    input.alt_srtt_ms = static_cast<double>(alt_srtt_ms);
    input.alt_jitter_ms = static_cast<double>(alt_jitter_ms);
    input.alt_loss_pct = static_cast<double>(alt_loss_pct);
    input.alt_bloat_ms = static_cast<double>(alt_bloat_ms);

    JiterStepOutput output{};
    if (jiter_engine_step(ctx->rust_engine, &input, &output) == 0) {
        return JNI_FALSE;
    }

    // Automatically synchronize C++ TrafficScheduler pacer with Rust controller output!
    const double link_hint = (bandwidth_mbps > 0.5) ? static_cast<double>(bandwidth_mbps) : 25.0;
    ctx->scheduler.configure_pacer(output.bg_pacer_ratio, link_hint);

    jdouble dvals[7] = {
        output.quality_score,
        output.srtt_ms,
        output.jitter_ms,
        output.bufferbloat_ms,
        output.rto_ms,
        output.bg_pacer_ratio,
        output.confidence,
    };
    jint ivals[6] = {
        static_cast<jint>(output.has_score),
        static_cast<jint>(output.quality_state),
        static_cast<jint>(output.fec_mode),
        static_cast<jint>(output.selected_route),
        static_cast<jint>(output.reason_flags),
        static_cast<jint>(output.abi_version),
    };
    env->SetDoubleArrayRegion(out_doubles, 0, 7, dvals);
    env->SetIntArrayRegion(out_ints, 0, 6, ivals);
    return JNI_TRUE;
#else
    (void)now_ms;
    (void)profile_id;
    (void)loss_pct;
    (void)bandwidth_mbps;
    (void)has_alt_route;
    (void)alt_srtt_ms;
    (void)alt_jitter_ms;
    (void)alt_loss_pct;
    (void)alt_bloat_ms;
    return JNI_FALSE;
#endif
}

JNIEXPORT void JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeConfigurePacer(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jdouble bg_pacer_ratio,
    jdouble estimated_link_mbps
) {
    (void)env;
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr) return;
    ctx->scheduler.configure_pacer(
        static_cast<double>(bg_pacer_ratio),
        static_cast<double>(estimated_link_mbps)
    );
}

JNIEXPORT jint JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeClassifyIpv4Tier(
    JNIEnv* env,
    jobject thiz,
    jbyteArray raw_packet
) {
    (void)thiz;
    if (raw_packet == nullptr) return -1;
    const jsize len = env->GetArrayLength(raw_packet);
    if (len < 20) return -1;

    jbyte* bytes = env->GetByteArrayElements(raw_packet, nullptr);
    if (bytes == nullptr) return -1;

    JiterPacketMeta meta{};
    const int ok = jiter_parse_ipv4_packet(
        reinterpret_cast<const uint8_t*>(bytes),
        static_cast<size_t>(len),
        &meta
    );
    env->ReleaseByteArrayElements(raw_packet, bytes, JNI_ABORT);
    return ok ? static_cast<jint>(meta.traffic_tier) : -1;
}

JNIEXPORT jboolean JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativePoolStats(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlongArray out_stats
) {
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr || out_stats == nullptr || env->GetArrayLength(out_stats) < 4) {
        return JNI_FALSE;
    }
    const jiter::PoolStats st = ctx->pool.stats();
    jlong vals[4] = {
        static_cast<jlong>(st.capacity),
        static_cast<jlong>(st.in_use),
        static_cast<jlong>(st.peak_in_use),
        static_cast<jlong>(st.exhausted_drops),
    };
    env->SetLongArrayRegion(out_stats, 0, 4, vals);
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeEnqueuePacket(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jbyteArray raw_packet,
    jint length,
    jlong now_ms,
    jint tier_override
) {
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr || raw_packet == nullptr || length <= 0) {
        return JNI_FALSE;
    }
    const jsize arr_len = env->GetArrayLength(raw_packet);
    if (length > arr_len) {
        return JNI_FALSE;
    }

    jbyte* bytes = env->GetByteArrayElements(raw_packet, nullptr);
    if (bytes == nullptr) {
        return JNI_FALSE;
    }

    const bool ok = ctx->scheduler.enqueue(
        reinterpret_cast<const uint8_t*>(bytes),
        static_cast<size_t>(length),
        static_cast<int64_t>(now_ms),
        static_cast<int>(tier_override)
    );
    env->ReleaseByteArrayElements(raw_packet, bytes, JNI_ABORT);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_jiter_app_bridge_NativeEngineBridge_nativeDequeuePacket(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong now_ms,
    jbyteArray out_buf,
    jintArray out_tier_and_len
) {
    (void)thiz;
    auto* ctx = from_handle(handle);
    if (ctx == nullptr || out_buf == nullptr || out_tier_and_len == nullptr) {
        return JNI_FALSE;
    }
    if (env->GetArrayLength(out_tier_and_len) < 2) {
        return JNI_FALSE;
    }

    jiter::PacketSlot* slot = ctx->scheduler.dequeue(static_cast<int64_t>(now_ms));
    if (slot == nullptr) {
        return JNI_FALSE;
    }

    const jsize cap = env->GetArrayLength(out_buf);
    const size_t copy_len = (slot->len <= static_cast<size_t>(cap))
        ? slot->len
        : static_cast<size_t>(cap);

    if (copy_len > 0) {
        env->SetByteArrayRegion(
            out_buf,
            0,
            static_cast<jsize>(copy_len),
            reinterpret_cast<const jbyte*>(slot->data)
        );
    }

    jint meta_out[2] = {
        static_cast<jint>(slot->meta.traffic_tier),
        static_cast<jint>(copy_len),
    };
    env->SetIntArrayRegion(out_tier_and_len, 0, 2, meta_out);
    ctx->pool.release(slot);
    return JNI_TRUE;
}

// ----------------------------------------------------------------------------
// Stage 6: JNI Bridge for Rust smoltcp Transparent Local TCP Stack
// ----------------------------------------------------------------------------

#if JITER_HAS_RUST_MATH
static JiterLocalTcpHandle* local_tcp_from_handle(jlong ptr) {
    if (ptr == 0) {
        return nullptr;
    }
    return reinterpret_cast<JiterLocalTcpHandle*>(static_cast<uintptr_t>(ptr));
}
#endif

JNIEXPORT jboolean JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeIsSupported(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
#if JITER_HAS_RUST_MATH
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

JNIEXPORT jlong JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeCreate(
    JNIEnv* env,
    jobject thiz,
    jint mtu,
    jlong seed
) {
    (void)env;
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = jiter_local_tcp_create(
        static_cast<uint16_t>(mtu),
        static_cast<uint64_t>(seed)
    );
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(h));
#else
    (void)mtu;
    (void)seed;
    return 0;
#endif
}

JNIEXPORT void JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeDestroy(
    JNIEnv* env,
    jobject thiz,
    jlong handle
) {
    (void)env;
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h != nullptr) {
        jiter_local_tcp_destroy(h);
    }
#else
    (void)handle;
#endif
}

JNIEXPORT jint JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeIngestIpv4(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jbyteArray pkt,
    jint length,
    jint tier,
    jlong now_ms,
    jlongArray out_meta
) {
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h == nullptr || pkt == nullptr || length <= 0 || out_meta == nullptr) {
        return -1;
    }
    if (length > env->GetArrayLength(pkt) || env->GetArrayLength(out_meta) < 3) {
        return -1;
    }
    jbyte* bytes = env->GetByteArrayElements(pkt, nullptr);
    if (bytes == nullptr) {
        return -1;
    }
    uint64_t flow_id = 0;
    uint32_t dst_ipv4_be = 0;
    uint16_t dst_port = 0;
    const int32_t res = jiter_local_tcp_ingest_ipv4(
        h,
        reinterpret_cast<const uint8_t*>(bytes),
        static_cast<size_t>(length),
        static_cast<uint8_t>(tier & 0xFF),
        static_cast<int64_t>(now_ms),
        &flow_id,
        &dst_ipv4_be,
        &dst_port
    );
    env->ReleaseByteArrayElements(pkt, bytes, JNI_ABORT);
    if (res == 1) {
        jlong meta[3] = {
            static_cast<jlong>(flow_id),
            static_cast<jlong>(dst_ipv4_be),
            static_cast<jlong>(dst_port),
        };
        env->SetLongArrayRegion(out_meta, 0, 3, meta);
    }
    return static_cast<jint>(res);
#else
    (void)env;
    (void)handle;
    (void)pkt;
    (void)length;
    (void)tier;
    (void)now_ms;
    (void)out_meta;
    return -1;
#endif
}

JNIEXPORT void JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativePoll(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong now_ms
) {
    (void)env;
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h != nullptr) {
        jiter_local_tcp_poll(h, static_cast<int64_t>(now_ms));
    }
#else
    (void)handle;
    (void)now_ms;
#endif
}

JNIEXPORT jint JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativePopTxPacket(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jbyteArray out_buf
) {
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h == nullptr || out_buf == nullptr) {
        return 0;
    }
    const jsize cap = env->GetArrayLength(out_buf);
    if (cap <= 0) {
        return 0;
    }
    uint8_t tmp[2048];
    const size_t max_len = (static_cast<size_t>(cap) < sizeof(tmp))
        ? static_cast<size_t>(cap)
        : sizeof(tmp);
    const size_t n = jiter_local_tcp_pop_tx_packet(h, tmp, max_len);
    if (n > 0) {
        env->SetByteArrayRegion(
            out_buf,
            0,
            static_cast<jsize>(n),
            reinterpret_cast<const jbyte*>(tmp)
        );
    }
    return static_cast<jint>(n);
#else
    (void)env;
    (void)handle;
    (void)out_buf;
    return 0;
#endif
}

JNIEXPORT jint JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeRecvFromApp(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong flow_id,
    jbyteArray out_buf,
    jint max_len,
    jlong now_ms
) {
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h == nullptr || out_buf == nullptr || max_len <= 0) {
        return -2;
    }
    const jsize cap = env->GetArrayLength(out_buf);
    const jint clamped = (max_len < cap) ? max_len : cap;
    jbyte* buf = env->GetByteArrayElements(out_buf, nullptr);
    if (buf == nullptr) {
        return -2;
    }
    const int32_t res = jiter_local_tcp_recv_from_app(
        h,
        static_cast<uint64_t>(flow_id),
        reinterpret_cast<uint8_t*>(buf),
        static_cast<size_t>(clamped),
        static_cast<int64_t>(now_ms)
    );
    env->ReleaseByteArrayElements(out_buf, buf, res > 0 ? 0 : JNI_ABORT);
    return static_cast<jint>(res);
#else
    (void)env;
    (void)handle;
    (void)flow_id;
    (void)out_buf;
    (void)max_len;
    (void)now_ms;
    return -2;
#endif
}

JNIEXPORT jint JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeSendToApp(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong flow_id,
    jbyteArray data,
    jint offset,
    jint length,
    jlong now_ms
) {
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h == nullptr || data == nullptr || offset < 0 || length < 0) {
        return -1;
    }
    const jsize arr_len = env->GetArrayLength(data);
    if (offset + length > arr_len) {
        return -1;
    }
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    if (bytes == nullptr) {
        return -1;
    }
    const int32_t res = jiter_local_tcp_send_to_app(
        h,
        static_cast<uint64_t>(flow_id),
        reinterpret_cast<const uint8_t*>(bytes + offset),
        static_cast<size_t>(length),
        static_cast<int64_t>(now_ms)
    );
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return static_cast<jint>(res);
#else
    (void)env;
    (void)handle;
    (void)flow_id;
    (void)data;
    (void)offset;
    (void)length;
    (void)now_ms;
    return -1;
#endif
}

JNIEXPORT jint JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeCanSendToApp(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong flow_id
) {
    (void)env;
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h == nullptr) {
        return -1;
    }
    return static_cast<jint>(jiter_local_tcp_can_send_to_app(h, static_cast<uint64_t>(flow_id)));
#else
    (void)handle;
    (void)flow_id;
    return -1;
#endif
}

JNIEXPORT void JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeCloseFlow(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlong flow_id,
    jboolean abort
) {
    (void)env;
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h != nullptr) {
        jiter_local_tcp_close_flow(h, static_cast<uint64_t>(flow_id), abort ? 1u : 0u);
    }
#else
    (void)handle;
    (void)flow_id;
    (void)abort;
#endif
}

JNIEXPORT void JNICALL
Java_com_jiter_app_local_LocalTcpNativeBridge_nativeGetStats(
    JNIEnv* env,
    jobject thiz,
    jlong handle,
    jlongArray out_stats
) {
    (void)thiz;
#if JITER_HAS_RUST_MATH
    JiterLocalTcpHandle* h = local_tcp_from_handle(handle);
    if (h == nullptr || out_stats == nullptr || env->GetArrayLength(out_stats) < 4) {
        return;
    }
    uint32_t active = 0;
    uint64_t total = 0;
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
    jiter_local_tcp_stats(h, &active, &total, &rx_bytes, &tx_bytes);
    jlong out[4] = {
        static_cast<jlong>(active),
        static_cast<jlong>(total),
        static_cast<jlong>(rx_bytes),
        static_cast<jlong>(tx_bytes),
    };
    env->SetLongArrayRegion(out_stats, 0, 4, out);
#else
    (void)env;
    (void)handle;
    (void)out_stats;
#endif
}

} // extern "C"
