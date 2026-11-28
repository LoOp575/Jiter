//! JITER Rust Mathematical Engine
//!
//! Role in JITER's polyglot architecture:
//!   - **Rust** (`engine-rust/`): Mathematical engine, estimators, scoring, XOR FEC, and adaptive controller
//!   - **C** (`engine-native/c/`): Zero-copy packet parser & word-aligned GF(2) XOR kernel
//!   - **C++** (`engine-native/cpp/`): Slab PacketPool memory manager, Strict Priority Scheduler & JNI bridge
//!   - **Kotlin** (`android/`): Android UI, VpnService, Notification, Usage Access & swappable backend config

pub mod controller;
pub mod ewma;
pub mod fec;
pub mod ffi;
pub mod local_tcp;
pub mod scoring;

#[cfg(test)]
mod tests {
    use crate::controller::{AdaptiveController, FecMode, RouteChoice, RouteMetrics};
    use crate::ewma::BitwiseEwmaEstimator;
    use crate::fec::{FecFrame, InterleavedXorFecDecoder, InterleavedXorFecEncoder};
    use crate::ffi::{
        jiter_engine_abi_version, jiter_engine_create, jiter_engine_destroy, jiter_engine_step,
        jiter_engine_submit_rtt, JiterStepInput, JiterStepOutput, ENGINE_ABI_VERSION,
    };
    use crate::scoring::{
        evaluate_linear_cost, ColorStateMachine, QualityState, TrafficProfile,
        REASON_ROUTE_TO_NATIVE, REASON_ROUTE_TO_RELAY, REASON_VETO_GAME_LOSS,
    };

    #[test]
    fn ewma_rejects_invalid_and_out_of_order_samples() {
        let mut est = BitwiseEwmaEstimator::new();
        assert!(!est.update(0.0, 1_000));
        assert!(!est.update(-5.0, 1_000));
        assert!(!est.update(f64::NAN, 1_000));
        assert!(!est.update(f64::INFINITY, 1_000));
        assert!(!est.update(40_000.0, 1_000));
        assert!(!est.is_initialized());
        assert!(est.srtt_ms().is_none());

        assert!(est.update(20.0, 2_000));
        assert!(!est.update(22.0, 1_500));
        assert_eq!(est.sample_count(), 1);
    }

    #[test]
    fn ewma_scaled_bitwise_matches_rfc6298_float() {
        let samples = [30.0, 32.0, 29.0, 31.0, 30.0, 120.0, 31.0, 29.0, 30.0];
        let mut est = BitwiseEwmaEstimator::new();
        let mut srtt_f = samples[0];
        let mut var_f = samples[0] / 2.0;

        for (idx, &rtt) in samples.iter().enumerate() {
            assert!(est.update(rtt, (idx as i64) * 1_000));
            if idx > 0 {
                let err = rtt - srtt_f;
                var_f = 0.75 * var_f + 0.25 * err.abs();
                srtt_f = 0.875 * srtt_f + 0.125 * rtt;
            }
        }

        assert!((est.srtt_ms().unwrap() - srtt_f).abs() < 0.05);
        assert!((est.jitter_ms().unwrap() - var_f).abs() < 0.05);
        assert!(est.bufferbloat_ms().unwrap() > 0.0);
    }

    #[test]
    fn all_profile_weights_sum_to_one() {
        for p in [
            TrafficProfile::Game,
            TrafficProfile::Browser,
            TrafficProfile::Download,
            TrafficProfile::Streaming,
            TrafficProfile::Social,
            TrafficProfile::SafeBalanced,
        ] {
            let w = p.weights();
            let sum = w.w_rtt + w.w_jitter + w.w_loss + w.w_bloat + w.w_bw;
            assert!((sum - 1.0).abs() < 1e-6, "Profile {:?} sum = {}", p, sum);
        }
    }

    #[test]
    fn game_hard_veto_prevents_loss_compensation_trap() {
        let res = evaluate_linear_cost(20.0, 2.0, 10.0, 0.0, Some(40.0), TrafficProfile::Game, 20);
        assert_ne!(res.veto_flags & REASON_VETO_GAME_LOSS, 0);
        assert!(res.score_q <= 45.0);
    }

    #[test]
    fn color_hysteresis_and_stale_unknown() {
        let mut cm = ColorStateMachine::new(2_000, 1.0);
        assert_eq!(cm.update(Some(90.0), 0, false), QualityState::Green);
        assert_eq!(cm.update(Some(76.0), 3_000, false), QualityState::Green);
        assert_eq!(cm.update(Some(70.0), 3_500, false), QualityState::Yellow);
        assert_eq!(cm.update(Some(79.0), 6_000, false), QualityState::Yellow);
        assert_eq!(cm.update(Some(84.0), 6_500, false), QualityState::Green);
        assert_eq!(cm.update(None, 7_000, true), QualityState::Unknown);
    }

    #[test]
    fn xor_fec_variable_length_bit_exact_and_wire_roundtrip() {
        let mut enc = InterleavedXorFecEncoder::new(4, 1);
        let payloads: Vec<Vec<u8>> = vec![
            b"A".to_vec(),
            b"short_pkt".to_vec(),
            (0u8..100u8).collect(),
            vec![],
        ];
        let mut frames = Vec::new();
        for p in &payloads {
            frames.extend(enc.encode_packet(p));
        }
        assert_eq!(frames.len(), 5);

        // Verify wire round-trip
        let round_tripped: Vec<FecFrame> = frames
            .iter()
            .map(|f| FecFrame::from_wire_bytes(&f.to_wire_bytes()).unwrap())
            .collect();
        assert_eq!(frames, round_tripped);

        for drop_idx in 0..4 {
            let mut dec = InterleavedXorFecDecoder::new(64);
            let mut got = std::collections::HashMap::new();
            for (idx, fr) in round_tripped.iter().enumerate() {
                if idx == drop_idx {
                    continue;
                }
                for pkt in dec.receive(fr) {
                    got.insert(pkt.slot_index as usize, pkt.payload);
                }
            }
            assert_eq!(dec.recovered_count(), 1);
            assert_eq!(got.len(), 4);
            for slot in 0..4 {
                assert_eq!(got[&slot], payloads[slot]);
            }
        }
    }

    #[test]
    fn interleaved_stride_recovers_four_consecutive_drops() {
        let mut enc = InterleavedXorFecEncoder::new(4, 4);
        let mut dec = InterleavedXorFecDecoder::new(64);
        let sent: Vec<Vec<u8>> = (0..16)
            .map(|i| format!("burst_test_{:02}", i).into_bytes())
            .collect();
        let mut wire = Vec::new();
        for p in &sent {
            wire.extend(enc.encode_packet(p));
        }
        assert_eq!(wire.len(), 20);

        let mut recovered = std::collections::HashSet::new();
        for (idx, fr) in wire.iter().enumerate() {
            if (4..=7).contains(&idx) {
                continue;
            }
            for pkt in dec.receive(fr) {
                recovered.insert(pkt.payload);
            }
        }
        assert_eq!(dec.recovered_count(), 4);
        let expected: std::collections::HashSet<Vec<u8>> = sent.into_iter().collect();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn adaptive_controller_route_hysteresis_and_cooldown() {
        let mut ewma = BitwiseEwmaEstimator::new();
        for (i, &rtt) in [60.0, 115.0, 130.0, 125.0, 140.0, 135.0].iter().enumerate() {
            ewma.update(rtt, (i as i64) * 500);
        }

        let mut ctrl = AdaptiveController::new(10.0, 2_000);
        let dec = ctrl.step(
            3_000,
            TrafficProfile::Game,
            &ewma,
            3.0,
            Some(20.0),
            Some(RouteMetrics {
                srtt_ms: 18.0,
                jitter_ms: 2.0,
                loss_pct: 0.2,
                bufferbloat_ms: 2.0,
            }),
        );
        assert_eq!(dec.fec_mode, FecMode::XorK4Interleaved);
        assert!(dec.bg_pacer_ratio < 1.0);
        assert_eq!(dec.selected_route, RouteChoice::Relay);
        assert_ne!(dec.reason_flags & REASON_ROUTE_TO_RELAY, 0);

        // Cooldown holds route
        let during_cd = ctrl.step(
            4_000,
            TrafficProfile::Game,
            &ewma,
            3.0,
            Some(20.0),
            Some(RouteMetrics {
                srtt_ms: 10.0,
                jitter_ms: 1.0,
                loss_pct: 0.0,
                bufferbloat_ms: 0.0,
            }),
        );
        assert_eq!(during_cd.selected_route, RouteChoice::Relay);

        // Post-cooldown switches back
        let after_cd = ctrl.step(
            5_500,
            TrafficProfile::Game,
            &ewma,
            3.0,
            Some(20.0),
            Some(RouteMetrics {
                srtt_ms: 10.0,
                jitter_ms: 1.0,
                loss_pct: 0.0,
                bufferbloat_ms: 0.0,
            }),
        );
        assert_eq!(after_cd.selected_route, RouteChoice::Native);
        assert_ne!(after_cd.reason_flags & REASON_ROUTE_TO_NATIVE, 0);
    }

    #[test]
    fn c_ffi_roundtrip_works_safely() {
        assert_eq!(jiter_engine_abi_version(), ENGINE_ABI_VERSION);
        unsafe {
            let h = jiter_engine_create();
            assert!(!h.is_null());
            assert_eq!(jiter_engine_submit_rtt(h, 14.0, 1_000), 1);
            assert_eq!(jiter_engine_submit_rtt(h, 15.0, 2_000), 1);

            let input = JiterStepInput {
                now_ms: 2_500,
                profile_id: TrafficProfile::Game as u32,
                loss_pct: 0.0,
                bandwidth_mbps: 30.0,
                has_alt_route: 0,
                alt_srtt_ms: 0.0,
                alt_jitter_ms: 0.0,
                alt_loss_pct: 0.0,
                alt_bloat_ms: 0.0,
            };
            let mut output = std::mem::zeroed::<JiterStepOutput>();
            assert_eq!(jiter_engine_step(h, &input, &mut output), 1);
            assert_eq!(output.has_score, 1);
            assert!(output.quality_score > 90.0);
            assert_eq!(output.quality_state, QualityState::Green as u32);
            assert_eq!(output.abi_version, ENGINE_ABI_VERSION);

            jiter_engine_destroy(h);
        }
    }

    #[test]
    fn c_ffi_local_tcp_lifecycle_and_null_guards_work_safely() {
        use crate::ffi::{
            jiter_local_tcp_can_send_to_app, jiter_local_tcp_close_flow, jiter_local_tcp_create,
            jiter_local_tcp_destroy, jiter_local_tcp_ingest_ipv4, jiter_local_tcp_poll,
            jiter_local_tcp_pop_tx_packet, jiter_local_tcp_recv_from_app,
            jiter_local_tcp_send_to_app, jiter_local_tcp_stats,
        };

        unsafe {
            assert_eq!(
                jiter_local_tcp_ingest_ipv4(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ),
                -1
            );
            assert_eq!(jiter_local_tcp_can_send_to_app(std::ptr::null(), 1), -1);

            let h = jiter_local_tcp_create(1500, 42);
            assert!(!h.is_null());

            // Malformed truncated packet must be ignored safely without panicking
            let garbage = [0x45u8, 0x00, 0x00, 0x14, 0x00, 0x00];
            let mut fid = 0u64;
            let mut dst_ip = 0u32;
            let mut dst_port = 0u16;
            assert_eq!(
                jiter_local_tcp_ingest_ipv4(
                    h,
                    garbage.as_ptr(),
                    garbage.len(),
                    0,
                    100,
                    &mut fid,
                    &mut dst_ip,
                    &mut dst_port,
                ),
                0
            );
            jiter_local_tcp_poll(h, 200);
            let mut tx_buf = [0u8; 1500];
            assert_eq!(jiter_local_tcp_pop_tx_packet(h, tx_buf.as_mut_ptr(), tx_buf.len()), 0);
            assert_eq!(jiter_local_tcp_recv_from_app(h, 999, tx_buf.as_mut_ptr(), 64, 200), -2);
            assert_eq!(jiter_local_tcp_send_to_app(h, 999, garbage.as_ptr(), garbage.len(), 200), -1);
            jiter_local_tcp_close_flow(h, 999, 1);

            let mut active = 99u32;
            let mut total = 99u64;
            let mut rx = 99u64;
            let mut tx = 99u64;
            jiter_local_tcp_stats(h, &mut active, &mut total, &mut rx, &mut tx);
            assert_eq!(active, 0);
            assert_eq!(total, 0);
            assert_eq!(rx, 0);
            assert_eq!(tx, 0);

            jiter_local_tcp_destroy(h);
        }
    }
}
