#!/usr/bin/env python3
"""
JITER Simulation & Benchmark Suite

Runs four reproducible experiments proving how Formula #1 (Linear Cost + Veto),
Formula #2 (Scaled Bitwise EWMA), and Formula #3 (Interleaved XOR Parity FEC)
cooperate in a closed-loop latency-control engine.

Usage:
    python3 test-lab/simulations/run_experiments.py
"""

from __future__ import annotations

from collections import deque
import os
import random
import statistics
import time
from typing import Optional

from jiter_formulas import (
    AdaptiveController,
    BitwiseEwmaEstimator,
    FecMode,
    InterleavedXorFecDecoder,
    InterleavedXorFecEncoder,
    LinearCostScorer,
    RouteChoice,
    TrafficProfile,
)


def experiment_1_linear_cost() -> None:
    print("=" * 86)
    print("EXPERIMENT 1: FORMULA #1 — LINEAR COST FUNCTION + HARD VETO GUARDRAILS")
    print("=" * 86)
    scenarios = [
        ("A. Wi-Fi Fiber Stabil",           22,  2,  0.0,   5, 50.0),
        ("B. 4G Ramai + Bufferbloat",       68, 22,  1.5, 140, 18.0),
        ("C. Ping 20ms tapi Loss 10%!",     20,  2, 10.0,   5, 40.0),
        ("D. Speed 3 Mbps tapi Mulus",      30,  3,  0.0,  10,  3.0),
        ("E. ISP Macet / Routing Muter",   145, 38,  4.0, 180, 12.0),
        ("F. Lewat JITER Relay SG",         48,  5,  0.2,  15, 25.0),
    ]
    print(f"{'Skenario':<31} | {'Game':>6} | {'Brows':>6} | {'Downld':>6} | {'Stream':>6} | Guardrail Veto (Game)")
    print("-" * 102)
    for name, rtt, jit, loss, bloat, bw in scenarios:
        res = {
            p: LinearCostScorer.evaluate(rtt, jit, loss, bloat, bw, p)
            for p in (
                TrafficProfile.GAME,
                TrafficProfile.BROWSER,
                TrafficProfile.DOWNLOAD,
                TrafficProfile.STREAMING,
            )
        }
        veto = ", ".join(res[TrafficProfile.GAME].veto_reasons) or "-"
        print(
            f"{name:<31} | {res[TrafficProfile.GAME].score_q:6.1f} | "
            f"{res[TrafficProfile.BROWSER].score_q:6.1f} | "
            f"{res[TrafficProfile.DOWNLOAD].score_q:6.1f} | "
            f"{res[TrafficProfile.STREAMING].score_q:6.1f} | {veto}"
        )


def experiment_2_bitwise_ewma() -> None:
    print("\n" + "=" * 86)
    print("EXPERIMENT 2: FORMULA #2 — SCALED BITWISE EWMA (JACOBSON / RFC 6298)")
    print("=" * 86)
    samples = [30, 32, 29, 31, 30, 120, 31, 29, 30, 75, 78, 74, 76, 75, 77]
    est = BitwiseEwmaEstimator()
    srtt_f = float(samples[0])
    var_f = samples[0] / 2.0
    srtt_naive = samples[0]

    print(
        f"{'t':>2} | {'RTT':>4} | {'Float SRTT':>10} | {'Bitwise SRTT':>12} | "
        f"{'Bitwise Jit':>11} | {'Bloat':>6} | {'RTO':>6} | {'NaiveBit(BUG)':>13}"
    )
    print("-" * 86)
    for t, rtt in enumerate(samples):
        est.update(float(rtt), timestamp_ms=t * 1000)
        if t > 0:
            err_f = rtt - srtt_f
            var_f = 0.75 * var_f + 0.25 * abs(err_f)
            srtt_f = 0.875 * srtt_f + 0.125 * rtt
            srtt_naive += (rtt - srtt_naive) >> 3  # Demonstrates truncation bug without scaling!
        print(
            f"{t:2d} | {rtt:4d} | {srtt_f:10.2f} | {est.srtt_ms:12.2f} | "
            f"{est.jitter_ms:11.2f} | {est.bufferbloat_ms:6.1f} | {est.rto_ms:6.1f} | {srtt_naive:13d}"
        )


def experiment_3_xor_fec() -> None:
    print("\n" + "=" * 86)
    print("EXPERIMENT 3: FORMULA #3 — BITWISE XOR PARITY FEC (GF(2) + INTERLEAVED STRIDE)")
    print("=" * 86)

    # Concrete variable-length bit-exact recovery test
    enc = InterleavedXorFecEncoder(block_k=4, stride=1)
    dec = InterleavedXorFecDecoder()
    payloads = [
        b"PKT1:pos=(120,45)",
        b"PKT2:pos=(122,45),vel=3",
        b"PKT3:SKILL_ULTIMATE_TARGET=BOSS_01",  # variable length (34 bytes)
        b"PKT4:ack=991",
    ]
    frames = []
    for p in payloads:
        frames.extend(enc.encode_packet(p))

    # Drop frame index 2 (PKT3) in transit!
    recovered = None
    for idx, fr in enumerate(frames):
        if idx == 2:
            continue
        for _, slot, data in dec.receive(fr):
            if slot == 2:
                recovered = data
    print(f"Variable-length bit-exact recovery check: {recovered == payloads[2]} ({recovered!r})")

    # Monte Carlo over real encoder/decoder comparing random loss & wireless burst loss
    def run_fec_trial(k: int, stride: int, loss_rate: float, burst: bool, total_pkts: int = 8000):
        rng = random.Random(42)
        encoder = InterleavedXorFecEncoder(block_k=k, stride=stride)
        decoder = InterleavedXorFecDecoder(max_tracked_groups=64)

        in_bad = False
        p_bad_to_good = 0.40  # avg burst length = 2.5 consecutive wire packets
        p_good_to_bad = (loss_rate * p_bad_to_good) / max(1e-9, 1.0 - loss_rate)

        def is_lost() -> bool:
            nonlocal in_bad
            if not burst:
                return rng.random() < loss_rate
            if in_bad:
                lost = True
                if rng.random() < p_bad_to_good:
                    in_bad = False
                return lost
            if rng.random() < p_good_to_bad:
                in_bad = True
            return False

        raw_data_lost = 0
        delivered_ids = set()
        for seq in range(total_pkts):
            payload = f"G{seq:06d}".encode()
            for fr in encoder.encode_packet(payload):
                dropped = is_lost()
                if dropped:
                    if not fr.is_parity:
                        raw_data_lost += 1
                    continue
                for _, _, rec_payload in decoder.receive(fr):
                    delivered_ids.add(rec_payload)

        # Evaluate only full completed groups (ignore trailing partial stride at end)
        usable = total_pkts - (k * stride)
        final_lost = sum(1 for s in range(usable) if f"G{s:06d}".encode() not in delivered_ids)
        raw_pct = (raw_data_lost / total_pkts) * 100.0
        final_pct = (final_lost / usable) * 100.0
        red_pct = ((raw_pct - final_pct) / raw_pct * 100.0) if raw_pct > 0 else 0.0
        overhead = (1.0 / k) * 100.0
        return overhead, raw_pct, final_pct, red_pct

    print(f"\n{'Kondisi Jaringan':<28} | {'Config':<14} | {'Overhead':>8} | {'Raw Loss':>8} | {'Sisa Loss':>9} | {'Turun':>7}")
    print("-" * 88)
    trials = [
        ("Random Loss 2%",          4, 1, 0.02, False),
        ("Random Loss 5%",          4, 1, 0.05, False),
        ("Random Loss 5%",          2, 1, 0.05, False),
        ("Burst Loss 5% (Plain)",   4, 1, 0.05, True),
        ("Burst Loss 5% (Stride=4)",4, 4, 0.05, True),
        ("Burst Loss 5% (Stride=6)",4, 6, 0.05, True),
    ]
    for label, k, stride, lr, burst in trials:
        ov, raw_p, fin_p, red_p = run_fec_trial(k, stride, lr, burst)
        print(f"{label:<28} | k={k}, stride={stride:<2} | {ov:7.0f}% | {raw_p:7.2f}% | {fin_p:8.2f}% | {red_p:6.1f}%")


def experiment_4_closed_loop_game_and_streaming() -> None:
    print("\n" + "=" * 112)
    print("EXPERIMENT 4: CLOSED-LOOP GAME (60pkt/s) + STREAMING 1080p (8Mbps) + BACKGROUND DOWNLOAD (24Mbps)")
    print("=" * 112)

    def simulate(
        name: str,
        base_rtt_ms: float,
        relay_rtt_ms: Optional[float],
        cap_mbps: float,
        loss_pct: float,
        jiter_on: bool,
        duration_sec: int = 25,
    ) -> None:
        rng = random.Random(1337)
        cap_b_ms = (cap_mbps * 1e6 / 8.0) / 1000.0
        max_fifo_b = int(cap_b_ms * 180)  # 180 ms home-router bufferbloat queue

        fifo = deque()
        q_game = deque()
        q_stream = deque()
        q_bg = deque()

        ewma = BitwiseEwmaEstimator()
        ctrl = AdaptiveController(route_hysteresis_pts=10.0, route_cooldown_ms=3000)
        # k=2, stride=1 for ultra-low-latency Game UDP (~60 Kbps): max FEC wait = 16ms!
        fec_enc = InterleavedXorFecEncoder(block_k=2, stride=1)
        fec_dec = InterleavedXorFecDecoder(max_tracked_groups=64)

        active_base_rtt = base_rtt_ms
        bg_pacer = 1.0
        fec_mode = FecMode.OFF

        game_sent_ts: dict[int, int] = {}
        game_rtts: list[float] = []
        recent_loss = deque(maxlen=60)
        stream_bytes = 0
        seq_id = 0

        stream_acc = 0.0
        bg_acc = 0.0
        stream_b_ms = (8.0 * 1e6 / 8.0) / 1000.0
        bg_b_ms = (24.0 * 1e6 / 8.0) / 1000.0
        loss_p = loss_pct / 100.0

        def fifo_len_b() -> int:
            return sum(x[1] for x in fifo)

        for t in range(duration_sec * 1000):
            # 1. Game packets every 16 ms (~62.5 pkt/s, 120 bytes)
            if t % 16 == 0:
                seq_id += 1
                game_sent_ts[seq_id] = t
                payload = seq_id.to_bytes(4, "big") + b"\x00" * 116
                if jiter_on:
                    if fec_mode != FecMode.OFF:
                        for fr in fec_enc.encode_packet(payload):
                            q_game.append((t, 128, "GAME_FEC", fr))
                    else:
                        q_game.append((t, 120, "GAME_RAW", payload))
                else:
                    if fifo_len_b() + 120 <= max_fifo_b:
                        fifo.append((t, 120, "GAME_RAW", payload))

            # 2. Streaming 1080p (8 Mbps continuous)
            stream_acc += stream_b_ms
            while stream_acc >= 1400:
                stream_acc -= 1400
                if jiter_on:
                    if sum(x[1] for x in q_stream) < cap_b_ms * 15:
                        q_stream.append((t, 1400, "STREAM", None))
                else:
                    if fifo_len_b() + 1400 <= max_fifo_b:
                        fifo.append((t, 1400, "STREAM", None))

            # 3. Background download burst (seconds 4..21 trying to saturate 24 Mbps)
            if 4000 <= t <= 21000:
                bg_acc += bg_b_ms * (bg_pacer if jiter_on else 1.0)
                while bg_acc >= 1400:
                    bg_acc -= 1400
                    if jiter_on:
                        if sum(x[1] for x in q_bg) < cap_b_ms * 12:
                            q_bg.append((t, 1400, "BG", None))
                    else:
                        if fifo_len_b() + 1400 <= max_fifo_b:
                            fifo.append((t, 1400, "BG", None))

            # 4. Drain link for this 1 ms tick
            budget = cap_b_ms * (0.92 if jiter_on else 1.0)
            while budget > 0:
                item = None
                if not jiter_on:
                    if fifo and fifo[0][1] <= budget + 400:
                        item = fifo.popleft()
                else:
                    if q_game:
                        item = q_game.popleft()
                    elif q_stream and q_stream[0][1] <= budget + 400:
                        item = q_stream.popleft()
                    elif q_bg and q_bg[0][1] <= budget + 400:
                        item = q_bg.popleft()

                if item is None:
                    break

                enq_t, size, kind, obj = item
                budget -= size
                q_delay = t - enq_t

                if kind == "STREAM":
                    stream_bytes += size
                elif kind == "GAME_RAW":
                    dropped = rng.random() < loss_p
                    recent_loss.append(1 if dropped else 0)
                    if not dropped:
                        rtt = max(4.0, active_base_rtt + q_delay + rng.gauss(0, 1.2))
                        game_rtts.append(rtt)
                        ewma.update(rtt, timestamp_ms=t)
                elif kind == "GAME_FEC":
                    dropped = rng.random() < loss_p
                    if not obj.is_parity:
                        recent_loss.append(1 if dropped else 0)
                    if not dropped:
                        for _, _, rec_payload in fec_dec.receive(obj):
                            rec_seq = int.from_bytes(rec_payload[:4], "big")
                            origin_t = game_sent_ts.get(rec_seq, enq_t)
                            # Includes actual waiting delay if packet was recovered from parity!
                            total_q_and_fec_delay = (t - origin_t)
                            rtt = max(4.0, active_base_rtt + total_q_and_fec_delay + rng.gauss(0, 1.2))
                            game_rtts.append(rtt)
                            ewma.update(rtt, timestamp_ms=t)

            # 5. Closed-loop JITER controller every 250 ms
            if jiter_on and t > 0 and t % 250 == 0 and ewma.initialized:
                cur_loss = (sum(recent_loss) / len(recent_loss) * 100.0) if recent_loss else 0.0
                alt_probe = None
                if relay_rtt_ms is not None:
                    if ctrl.selected_route == RouteChoice.NATIVE:
                        alt_probe = (relay_rtt_ms, 2.5, cur_loss * 0.5, 2.0)
                    else:
                        alt_probe = (base_rtt_ms, 10.0, cur_loss, 20.0)
                decision = ctrl.step(
                    now_ms=t,
                    profile=TrafficProfile.GAME,
                    ewma=ewma,
                    loss_pct=cur_loss,
                    bandwidth_mbps=cap_mbps,
                    alternate_route_metrics=alt_probe,
                )
                bg_pacer = decision.bg_pacer_ratio
                fec_mode = decision.fec_mode
                if decision.selected_route == RouteChoice.RELAY and relay_rtt_ms is not None:
                    if active_base_rtt != relay_rtt_ms:
                        active_base_rtt = relay_rtt_ms
                        ewma.reset_baseline(relay_rtt_ms)
                elif decision.selected_route == RouteChoice.NATIVE:
                    if active_base_rtt != base_rtt_ms:
                        active_base_rtt = base_rtt_ms
                        ewma.reset_baseline(base_rtt_ms)

        game_rtts.sort()
        med = statistics.median(game_rtts) if game_rtts else 0.0
        p95 = game_rtts[int(len(game_rtts) * 0.95)] if game_rtts else 0.0
        final_loss = (1.0 - len(game_rtts) / max(1, seq_id)) * 100.0
        stream_mbps = (stream_bytes * 8.0) / duration_sec / 1e6
        tag = "WITH JITER" if jiter_on else "NO JITER  "
        print(
            f"{name:<32} | {tag} | Med:{med:5.1f}ms | P95:{p95:5.1f}ms | "
            f"Loss:{final_loss:4.2f}% | FEC_Rec:{fec_dec.recovered_count:3d} | Stream:{stream_mbps:4.1f}Mbps"
        )

    cases = [
        ("1. Wi-Fi Fiber -> Server JKT",     11.0, None, 25.0, 2.5),
        ("2. Wi-Fi Fiber -> Server SG",      16.0, None, 25.0, 2.5),
        ("3. ISP Muter (65ms) -> Relay SG",  65.0, 17.0, 25.0, 3.0),
        ("4. 4G LTE -> Server JKT (Fisika)", 32.0, None, 20.0, 3.0),
    ]
    for title, base, relay, cap, lp in cases:
        simulate(title, base, relay, cap, lp, jiter_on=False)
        simulate(title, base, relay, cap, lp, jiter_on=True)
        print("-" * 112)


if __name__ == "__main__":
    t_start = time.perf_counter()
    experiment_1_linear_cost()
    experiment_2_bitwise_ewma()
    experiment_3_xor_fec()
    experiment_4_closed_loop_game_and_streaming()
    print(f"\nAll experiments completed in {(time.perf_counter() - t_start):.2f}s.")
