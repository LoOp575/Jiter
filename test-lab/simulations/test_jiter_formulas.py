"""Unit tests for JITER core mathematical engines and closed-loop controller."""

import math
import unittest

from jiter_formulas import (
    AdaptiveController,
    BitwiseEwmaEstimator,
    ColorStateMachine,
    FecMode,
    InterleavedXorFecDecoder,
    InterleavedXorFecEncoder,
    LinearCostScorer,
    PROFILE_WEIGHTS,
    QualityState,
    RouteChoice,
    TrafficProfile,
)


class TestBitwiseEwmaEstimator(unittest.TestCase):
    def test_rejects_invalid_and_out_of_order_samples(self) -> None:
        est = BitwiseEwmaEstimator()
        self.assertFalse(est.update(0.0, 1000))
        self.assertFalse(est.update(-5.0, 1000))
        self.assertFalse(est.update(float("nan"), 1000))
        self.assertFalse(est.update(float("inf"), 1000))
        self.assertFalse(est.update(40_000.0, 1000))  # >30s bound
        self.assertFalse(est.initialized)
        self.assertIsNone(est.srtt_ms)

        self.assertTrue(est.update(20.0, 2000))
        self.assertFalse(est.update(22.0, 1500))  # out-of-order timestamp
        self.assertEqual(est.sample_count, 1)

    def test_scaled_bitwise_matches_rfc6298_float_without_truncation(self) -> None:
        samples = [30.0, 32.0, 29.0, 31.0, 30.0, 120.0, 31.0, 29.0, 30.0]
        est = BitwiseEwmaEstimator()
        srtt_f = samples[0]
        var_f = samples[0] / 2.0

        for idx, rtt in enumerate(samples):
            self.assertTrue(est.update(rtt, idx * 1000))
            if idx > 0:
                err = rtt - srtt_f
                var_f = 0.75 * var_f + 0.25 * abs(err)
                srtt_f = 0.875 * srtt_f + 0.125 * rtt

        assert est.srtt_ms is not None and est.jitter_ms is not None
        self.assertLess(abs(est.srtt_ms - srtt_f), 0.05)
        self.assertLess(abs(est.jitter_ms - var_f), 0.05)
        self.assertGreater(est.bufferbloat_ms, 0.0)  # spike elevated SRTT above min_rtt=29ms

    def test_stale_detection(self) -> None:
        est = BitwiseEwmaEstimator()
        self.assertTrue(est.is_stale(now_ms=1000))
        est.update(15.0, timestamp_ms=1000)
        self.assertFalse(est.is_stale(now_ms=5000, max_age_ms=10_000))
        self.assertTrue(est.is_stale(now_ms=12_000, max_age_ms=10_000))


class TestLinearCostScorerAndHysteresis(unittest.TestCase):
    def test_all_profile_weights_sum_to_one(self) -> None:
        for profile, w in PROFILE_WEIGHTS.items():
            total = w.w_rtt + w.w_jitter + w.w_loss + w.w_bloat + w.w_bw
            self.assertTrue(math.isclose(total, 1.0, abs_tol=1e-6), msg=f"{profile}: {total}")

    def test_game_hard_veto_prevents_loss_compensation_trap(self) -> None:
        # 20ms ping, 2ms jitter, 0 bloat, 40Mbps BUT 10% packet loss!
        res = LinearCostScorer.evaluate(
            srtt_ms=20.0,
            jitter_ms=2.0,
            loss_pct=10.0,
            bufferbloat_ms=0.0,
            bandwidth_mbps=40.0,
            profile=TrafficProfile.GAME,
        )
        self.assertIn("VETO_GAME_CRITICAL_LOSS", res.veto_reasons)
        self.assertLessEqual(res.score_q, 45.0)

    def test_missing_bandwidth_reduces_confidence_instead_of_zeroing(self) -> None:
        res = LinearCostScorer.evaluate(
            srtt_ms=15.0,
            jitter_ms=2.0,
            loss_pct=0.0,
            bufferbloat_ms=2.0,
            bandwidth_mbps=None,
            profile=TrafficProfile.DOWNLOAD,
            sample_count=20,
        )
        self.assertEqual(res.components["W"], 0.0)
        self.assertLess(res.confidence, 1.0)

    def test_color_hysteresis_and_stale_unknown(self) -> None:
        cm = ColorStateMachine(min_dwell_ms=2000, ewma_alpha=1.0)
        self.assertEqual(cm.update(90.0, now_ms=0), QualityState.GREEN)
        # Mild drop to 76 stays GREEN (band < 75 needed to drop)
        self.assertEqual(cm.update(76.0, now_ms=3000), QualityState.GREEN)
        # Drop to 70 after dwell -> YELLOW
        self.assertEqual(cm.update(70.0, now_ms=3500), QualityState.YELLOW)
        # Recovery to 79 stays YELLOW (needs >= 82 to return GREEN)
        self.assertEqual(cm.update(79.0, now_ms=6000), QualityState.YELLOW)
        # Recovery to 84 after dwell -> GREEN
        self.assertEqual(cm.update(84.0, now_ms=6500), QualityState.GREEN)
        # Stale -> UNKNOWN immediately
        self.assertEqual(cm.update(None, now_ms=7000, is_stale=True), QualityState.UNKNOWN)


class TestInterleavedXorFec(unittest.TestCase):
    def test_bit_exact_recovery_variable_length_payloads(self) -> None:
        enc = InterleavedXorFecEncoder(block_k=4, stride=1)
        payloads = [
            b"A",
            b"short_pkt",
            b"LONG_GAME_STATE_UPDATE:" + bytes(range(100)),
            b"",  # even empty payload works!
        ]
        frames = []
        for p in payloads:
            frames.extend(enc.encode_packet(p))
        self.assertEqual(len(frames), 5)  # 4 data + 1 parity

        # Test dropping EACH of the 4 data slots independently
        for drop_idx in range(4):
            dec = InterleavedXorFecDecoder()
            got = {}
            for idx, fr in enumerate(frames):
                if idx == drop_idx:
                    continue
                for _, slot, data in dec.receive(fr):
                    got[slot] = data
            self.assertEqual(dec.recovered_count, 1)
            self.assertEqual(len(got), 4)
            for slot in range(4):
                self.assertEqual(got[slot], payloads[slot])

    def test_interleaved_stride_recovers_consecutive_burst_loss(self) -> None:
        # With stride=4 and k=4, losing 4 consecutive wire packets drops only 1 packet per group!
        enc = InterleavedXorFecEncoder(block_k=4, stride=4)
        dec = InterleavedXorFecDecoder()
        sent = [f"burst_test_{i:02d}".encode() for i in range(16)]
        wire = []
        for p in sent:
            wire.extend(enc.encode_packet(p))
        self.assertEqual(len(wire), 20)  # 16 data + 4 parity

        # Drop 4 consecutive wire packets (indices 4, 5, 6, 7) -> 100% recoverable!
        drop_set = {4, 5, 6, 7}
        recovered_payloads = set()
        for idx, fr in enumerate(wire):
            if idx in drop_set:
                continue
            for _, _, data in dec.receive(fr):
                recovered_payloads.add(data)

        self.assertEqual(dec.recovered_count, 4)
        self.assertEqual(recovered_payloads, set(sent))

    def test_two_drops_in_same_group_not_falsely_recovered(self) -> None:
        enc = InterleavedXorFecEncoder(block_k=4, stride=1)
        dec = InterleavedXorFecDecoder()
        frames = []
        for i in range(4):
            frames.extend(enc.encode_packet(f"pkt{i}".encode()))

        # Drop slots 0 and 1 in the same group
        got = []
        for idx, fr in enumerate(frames):
            if idx in (0, 1):
                continue
            got.extend(dec.receive(fr))
        self.assertEqual(dec.recovered_count, 0)
        self.assertEqual(len(got), 2)


class TestAdaptiveController(unittest.TestCase):
    def test_closed_loop_enables_fec_pacer_and_switches_to_better_relay(self) -> None:
        ewma = BitwiseEwmaEstimator()
        # Simulate ISP route degraded: 120ms ping, jittery, bloat rising
        for i, rtt in enumerate([60.0, 115.0, 130.0, 125.0, 140.0, 135.0]):
            ewma.update(rtt, timestamp_ms=i * 500)

        ctrl = AdaptiveController(route_hysteresis_pts=10.0, route_cooldown_ms=2000)
        dec = ctrl.step(
            now_ms=3000,
            profile=TrafficProfile.GAME,
            ewma=ewma,
            loss_pct=3.0,
            bandwidth_mbps=20.0,
            alternate_route_metrics=(18.0, 2.0, 0.2, 2.0),  # Local SG/JKT relay much cleaner!
        )
        self.assertEqual(dec.fec_mode, FecMode.XOR_K4_INTERLEAVED)
        self.assertLess(dec.bg_pacer_ratio, 1.0)
        self.assertEqual(dec.selected_route, RouteChoice.RELAY)
        self.assertIn("ROUTE_SWITCH_TO_RELAY", dec.reason_codes)

        # Within cooldown (now_ms=4000), must NOT flap back even if alternate looks better
        dec_cooldown = ctrl.step(
            now_ms=4000,
            profile=TrafficProfile.GAME,
            ewma=ewma,
            loss_pct=3.0,
            bandwidth_mbps=20.0,
            alternate_route_metrics=(10.0, 1.0, 0.0, 0.0),
        )
        self.assertEqual(dec_cooldown.selected_route, RouteChoice.RELAY)

        # After cooldown (now_ms=5500), if active relay degrades and native is cleaner, switch back
        dec_back = ctrl.step(
            now_ms=5500,
            profile=TrafficProfile.GAME,
            ewma=ewma,
            loss_pct=3.0,
            bandwidth_mbps=20.0,
            alternate_route_metrics=(10.0, 1.0, 0.0, 0.0),
        )
        self.assertEqual(dec_back.selected_route, RouteChoice.NATIVE)
        self.assertIn("ROUTE_SWITCH_TO_NATIVE", dec_back.reason_codes)

    def test_fec_disabled_for_download_profile(self) -> None:
        ewma = BitwiseEwmaEstimator()
        ewma.update(30.0, timestamp_ms=1000)
        ctrl = AdaptiveController()
        dec = ctrl.step(
            now_ms=1500,
            profile=TrafficProfile.DOWNLOAD,
            ewma=ewma,
            loss_pct=3.0,
            bandwidth_mbps=30.0,
        )
        self.assertEqual(dec.fec_mode, FecMode.OFF)
        self.assertEqual(dec.bg_pacer_ratio, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
