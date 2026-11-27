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

} // extern "C"
