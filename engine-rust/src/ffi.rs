//! Narrow, versioned C-ABI FFI surface for linking `jiter-math` into the
//! C/C++ network engine and Android NDK JNI bridge.
//!
//! Every `extern "C"` entrypoint is guarded with `std::panic::catch_unwind` so no Rust
//! panic can ever cross the C-ABI boundary and abort (`SIGABRT`) the host Android process.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::controller::{AdaptiveController, RouteMetrics};
use crate::ewma::BitwiseEwmaEstimator;
use crate::local_tcp::{IngestOutcome, LocalTcpStack};
use crate::scoring::TrafficProfile;

pub const ENGINE_ABI_VERSION: u32 = 1;

pub struct JiterEngineHandle {
    ewma: BitwiseEwmaEstimator,
    controller: AdaptiveController,
}

#[repr(C)]
pub struct JiterStepInput {
    pub now_ms: i64,
    pub profile_id: u32,
    pub loss_pct: f64,
    pub bandwidth_mbps: f64, // < 0.0 means unknown / unavailable
    pub has_alt_route: u8,
    pub alt_srtt_ms: f64,
    pub alt_jitter_ms: f64,
    pub alt_loss_pct: f64,
    pub alt_bloat_ms: f64,
}

#[repr(C)]
pub struct JiterStepOutput {
    pub has_score: u8,
    pub quality_score: f64,
    pub srtt_ms: f64,
    pub jitter_ms: f64,
    pub bufferbloat_ms: f64,
    pub rto_ms: f64,
    pub bg_pacer_ratio: f64,
    pub confidence: f64,
    pub quality_state: u32,
    pub fec_mode: u32,
    pub selected_route: u32,
    pub reason_flags: u32,
    pub abi_version: u32,
}

#[no_mangle]
pub extern "C" fn jiter_engine_abi_version() -> u32 {
    ENGINE_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn jiter_engine_create() -> *mut JiterEngineHandle {
    catch_unwind(AssertUnwindSafe(|| {
        Box::into_raw(Box::new(JiterEngineHandle {
            ewma: BitwiseEwmaEstimator::new(),
            controller: AdaptiveController::default(),
        }))
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn jiter_engine_destroy(handle: *mut JiterEngineHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn jiter_engine_reset(handle: *mut JiterEngineHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(engine) = handle.as_mut() {
            engine.ewma.reset();
            engine.controller.reset();
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn jiter_engine_reset_baseline(
    handle: *mut JiterEngineHandle,
    new_min_rtt_ms: f64,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(engine) = handle.as_mut() {
            let opt = if new_min_rtt_ms.is_finite() && new_min_rtt_ms > 0.0 {
                Some(new_min_rtt_ms)
            } else {
                None
            };
            engine.ewma.reset_baseline(opt);
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn jiter_engine_submit_rtt(
    handle: *mut JiterEngineHandle,
    rtt_ms: f64,
    timestamp_ms: i64,
) -> u8 {
    catch_unwind(AssertUnwindSafe(|| match handle.as_mut() {
        Some(engine) => u8::from(engine.ewma.update(rtt_ms, timestamp_ms)),
        None => 0,
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn jiter_engine_step(
    handle: *mut JiterEngineHandle,
    input: *const JiterStepInput,
    output: *mut JiterStepOutput,
) -> u8 {
    catch_unwind(AssertUnwindSafe(|| {
        let (Some(engine), Some(inp), Some(out)) =
            (handle.as_mut(), input.as_ref(), output.as_mut())
        else {
            return 0;
        };

        let profile = TrafficProfile::from_u32(inp.profile_id);
        let bw = if inp.bandwidth_mbps.is_finite() && inp.bandwidth_mbps >= 0.0 {
            Some(inp.bandwidth_mbps)
        } else {
            None
        };
        let alt = if inp.has_alt_route != 0 {
            Some(RouteMetrics {
                srtt_ms: inp.alt_srtt_ms,
                jitter_ms: inp.alt_jitter_ms,
                loss_pct: inp.alt_loss_pct,
                bufferbloat_ms: inp.alt_bloat_ms,
            })
        } else {
            None
        };

        let dec = engine
            .controller
            .step(inp.now_ms, profile, &engine.ewma, inp.loss_pct, bw, alt);

        out.has_score = u8::from(dec.quality_score.is_some());
        out.quality_score = dec.quality_score.unwrap_or(-1.0);
        out.srtt_ms = engine.ewma.srtt_ms().unwrap_or(-1.0);
        out.jitter_ms = engine.ewma.jitter_ms().unwrap_or(-1.0);
        out.bufferbloat_ms = engine.ewma.bufferbloat_ms().unwrap_or(-1.0);
        out.rto_ms = engine.ewma.rto_ms().unwrap_or(-1.0);
        out.bg_pacer_ratio = dec.bg_pacer_ratio;
        out.confidence = dec.confidence;
        out.quality_state = dec.quality_state as u32;
        out.fec_mode = dec.fec_mode as u32;
        out.selected_route = dec.selected_route as u32;
        out.reason_flags = dec.reason_flags;
        out.abi_version = ENGINE_ABI_VERSION;
        1
    }))
    .unwrap_or(0)
}

// ----------------------------------------------------------------------------
// Stage 6: Transparent User-Space TCP Stack (`smoltcp`) C-ABI FFI
// ----------------------------------------------------------------------------

pub struct JiterLocalTcpHandle {
    stack: LocalTcpStack,
}

#[no_mangle]
pub extern "C" fn jiter_local_tcp_create(mtu: u16, seed: u64) -> *mut JiterLocalTcpHandle {
    catch_unwind(AssertUnwindSafe(|| {
        Box::into_raw(Box::new(JiterLocalTcpHandle {
            stack: LocalTcpStack::new(mtu, seed),
        }))
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_destroy(handle: *mut JiterLocalTcpHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    }));
}

/// Returns:
///   1 = brand-new TCP flow created (`out_flow_id`, `out_dst_ipv4_be`, `out_dst_port` populated)
///   0 = packet handled for existing flow or ignored
///  -1 = invalid arguments or guarded panic
#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_ingest_ipv4(
    handle: *mut JiterLocalTcpHandle,
    pkt: *const u8,
    len: usize,
    tier: u8,
    now_ms: i64,
    out_flow_id: *mut u64,
    out_dst_ipv4_be: *mut u32,
    out_dst_port: *mut u16,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(h) = handle.as_mut() else {
            return -1;
        };
        if pkt.is_null() || len == 0 {
            return -1;
        }
        let slice = std::slice::from_raw_parts(pkt, len);
        match h.stack.ingest_ipv4(slice, tier, now_ms) {
            IngestOutcome::NewFlow {
                flow_id,
                dst_ipv4_be,
                dst_port,
            } => {
                if let Some(p) = out_flow_id.as_mut() {
                    *p = flow_id;
                }
                if let Some(p) = out_dst_ipv4_be.as_mut() {
                    *p = dst_ipv4_be;
                }
                if let Some(p) = out_dst_port.as_mut() {
                    *p = dst_port;
                }
                1
            }
            IngestOutcome::ExistingFlow | IngestOutcome::Ignored => 0,
        }
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_poll(handle: *mut JiterLocalTcpHandle, now_ms: i64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(h) = handle.as_mut() {
            h.stack.poll(now_ms);
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_pop_tx_packet(
    handle: *mut JiterLocalTcpHandle,
    out_buf: *mut u8,
    max_len: usize,
) -> usize {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(h) = handle.as_mut() else {
            return 0;
        };
        if out_buf.is_null() || max_len == 0 {
            return 0;
        }
        let Some(pkt) = h.stack.pop_tx_packet() else {
            return 0;
        };
        let copy_len = pkt.len().min(max_len);
        std::ptr::copy_nonoverlapping(pkt.as_ptr(), out_buf, copy_len);
        copy_len
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_recv_from_app(
    handle: *mut JiterLocalTcpHandle,
    flow_id: u64,
    out_buf: *mut u8,
    max_len: usize,
    now_ms: i64,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(h) = handle.as_mut() else {
            return -2;
        };
        if out_buf.is_null() || max_len == 0 {
            return h.stack.recv_from_app(flow_id, &mut [], now_ms);
        }
        let slice = std::slice::from_raw_parts_mut(out_buf, max_len);
        h.stack.recv_from_app(flow_id, slice, now_ms)
    }))
    .unwrap_or(-2)
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_send_to_app(
    handle: *mut JiterLocalTcpHandle,
    flow_id: u64,
    data: *const u8,
    len: usize,
    now_ms: i64,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(h) = handle.as_mut() else {
            return -1;
        };
        if data.is_null() || len == 0 {
            return h.stack.send_to_app(flow_id, &[], now_ms);
        }
        let slice = std::slice::from_raw_parts(data, len);
        h.stack.send_to_app(flow_id, slice, now_ms)
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_can_send_to_app(
    handle: *const JiterLocalTcpHandle,
    flow_id: u64,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| match handle.as_ref() {
        Some(h) => h.stack.can_send_to_app(flow_id),
        None => -1,
    }))
    .unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_close_flow(
    handle: *mut JiterLocalTcpHandle,
    flow_id: u64,
    abort: u8,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(h) = handle.as_mut() {
            h.stack.close_flow(flow_id, abort != 0);
        }
    }));
}

#[no_mangle]
pub unsafe extern "C" fn jiter_local_tcp_stats(
    handle: *const JiterLocalTcpHandle,
    out_active: *mut u32,
    out_total: *mut u64,
    out_rx_bytes: *mut u64,
    out_tx_bytes: *mut u64,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(h) = handle.as_ref() else {
            return;
        };
        let st = h.stack.stats();
        if let Some(p) = out_active.as_mut() {
            *p = st.active_flows;
        }
        if let Some(p) = out_total.as_mut() {
            *p = st.total_flows;
        }
        if let Some(p) = out_rx_bytes.as_mut() {
            *p = st.app_rx_bytes;
        }
        if let Some(p) = out_tx_bytes.as_mut() {
            *p = st.app_tx_bytes;
        }
    }));
}
