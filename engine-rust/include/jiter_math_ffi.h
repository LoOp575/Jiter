#ifndef JITER_MATH_FFI_H
#define JITER_MATH_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JITER_ENGINE_ABI_VERSION 1u

/* TrafficProfile codes */
#define JITER_PROFILE_GAME          0u
#define JITER_PROFILE_BROWSER       1u
#define JITER_PROFILE_DOWNLOAD      2u
#define JITER_PROFILE_STREAMING     3u
#define JITER_PROFILE_SOCIAL        4u
#define JITER_PROFILE_SAFE_BALANCED 5u

/* QualityState codes */
#define JITER_QUALITY_UNKNOWN 0u
#define JITER_QUALITY_GREEN   1u
#define JITER_QUALITY_YELLOW  2u
#define JITER_QUALITY_RED     3u

/* FecMode codes */
#define JITER_FEC_OFF                0u
#define JITER_FEC_XOR_K4_INTERLEAVED 1u
#define JITER_FEC_XOR_K2_INTERLEAVED 2u
#define JITER_FEC_DUPLICATE          3u

/* RouteChoice codes */
#define JITER_ROUTE_NATIVE 0u
#define JITER_ROUTE_RELAY  1u

/* Reason code bitmask flags */
#define JITER_REASON_STALE_SAMPLES        (1u << 0)
#define JITER_REASON_VETO_GAME_LOSS       (1u << 1)
#define JITER_REASON_VETO_GAME_BLOAT      (1u << 2)
#define JITER_REASON_VETO_GAME_MIN_BW     (1u << 3)
#define JITER_REASON_VETO_STREAM_STARVED  (1u << 4)
#define JITER_REASON_VETO_STREAM_LOSS     (1u << 5)
#define JITER_REASON_PACER_THROTTLE_BG    (1u << 6)
#define JITER_REASON_PACER_HEADROOM       (1u << 7)
#define JITER_REASON_PACER_FULL           (1u << 8)
#define JITER_REASON_FEC_K4               (1u << 9)
#define JITER_REASON_FEC_K2               (1u << 10)
#define JITER_REASON_FEC_STANDBY          (1u << 11)
#define JITER_REASON_ROUTE_TO_RELAY       (1u << 12)
#define JITER_REASON_ROUTE_TO_NATIVE      (1u << 13)

typedef struct JiterEngineHandle JiterEngineHandle;

typedef struct {
    int64_t now_ms;
    uint32_t profile_id;
    double loss_pct;
    double bandwidth_mbps;        /* Negative (< 0.0) indicates unknown / unavailable */
    uint8_t has_alt_route;
    double alt_srtt_ms;
    double alt_jitter_ms;
    double alt_loss_pct;
    double alt_bloat_ms;
} JiterStepInput;

typedef struct {
    uint8_t has_score;
    double quality_score;
    double srtt_ms;
    double jitter_ms;
    double bufferbloat_ms;
    double rto_ms;
    double bg_pacer_ratio;
    double confidence;
    uint32_t quality_state;
    uint32_t fec_mode;
    uint32_t selected_route;
    uint32_t reason_flags;
    uint32_t abi_version;
} JiterStepOutput;

uint32_t jiter_engine_abi_version(void);
JiterEngineHandle* jiter_engine_create(void);
void jiter_engine_destroy(JiterEngineHandle* handle);
void jiter_engine_reset(JiterEngineHandle* handle);
void jiter_engine_reset_baseline(JiterEngineHandle* handle, double new_min_rtt_ms);

/* Returns 1 if accepted, 0 if rejected as invalid / out-of-order */
uint8_t jiter_engine_submit_rtt(JiterEngineHandle* handle, double rtt_ms, int64_t timestamp_ms);

/* Evaluates Formulas #2 -> #1 -> #3 + Pacer + Route Selector; returns 1 on success */
uint8_t jiter_engine_step(
    JiterEngineHandle* handle,
    const JiterStepInput* input,
    JiterStepOutput* output
);

/* Stage 6: Transparent User-Space TCP Stack (smoltcp) */
typedef struct JiterLocalTcpHandle JiterLocalTcpHandle;

JiterLocalTcpHandle* jiter_local_tcp_create(uint16_t mtu, uint64_t seed);
void jiter_local_tcp_destroy(JiterLocalTcpHandle* handle);

int32_t jiter_local_tcp_ingest_ipv4(
    JiterLocalTcpHandle* handle,
    const uint8_t* pkt,
    size_t len,
    uint8_t tier,
    int64_t now_ms,
    uint64_t* out_flow_id,
    uint32_t* out_dst_ipv4_be,
    uint16_t* out_dst_port
);

void jiter_local_tcp_poll(JiterLocalTcpHandle* handle, int64_t now_ms);

size_t jiter_local_tcp_pop_tx_packet(
    JiterLocalTcpHandle* handle,
    uint8_t* out_buf,
    size_t max_len
);

int32_t jiter_local_tcp_recv_from_app(
    JiterLocalTcpHandle* handle,
    uint64_t flow_id,
    uint8_t* out_buf,
    size_t max_len,
    int64_t now_ms
);

int32_t jiter_local_tcp_send_to_app(
    JiterLocalTcpHandle* handle,
    uint64_t flow_id,
    const uint8_t* data,
    size_t len,
    int64_t now_ms
);

int32_t jiter_local_tcp_can_send_to_app(
    const JiterLocalTcpHandle* handle,
    uint64_t flow_id
);

void jiter_local_tcp_close_flow(
    JiterLocalTcpHandle* handle,
    uint64_t flow_id,
    uint8_t abort
);

void jiter_local_tcp_stats(
    const JiterLocalTcpHandle* handle,
    uint32_t* out_active,
    uint64_t* out_total,
    uint64_t* out_rx_bytes,
    uint64_t* out_tx_bytes
);

#ifdef __cplusplus
}
#endif

#endif /* JITER_MATH_FFI_H */
