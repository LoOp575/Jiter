"""
JITER Reference Core Engine (Python Simulation & Verification Lab)

Implements the three cooperating mathematical engines defined in JITER Blueprint v2.0:
  1. Formula #1: Linear Cost Function + Hard Veto Guardrails + Hysteresis State Machine
  2. Formula #2: Scaled Bitwise EWMA / Jacobson's Algorithm (RFC 6298)
  3. Formula #3: Bitwise XOR Parity FEC over GF(2) with Interleaved Stride & variable-length framing
  4. Closed-Loop AdaptiveController coordinating #2 -> #1 -> #3 + Anti-Bufferbloat Pacer + Route Selector
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
import struct
from typing import Dict, List, Optional, Tuple


# ============================================================================
# Shared Enums & Profile Definitions
# ============================================================================

class TrafficProfile(str, Enum):
    GAME = "Game"
    BROWSER = "Browser"
    DOWNLOAD = "Download"
    STREAMING = "Streaming"
    SOCIAL = "Social"
    SAFE_BALANCED = "SafeBalanced"


class QualityState(str, Enum):
    UNKNOWN = "UNKNOWN"
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


class FecMode(str, Enum):
    OFF = "OFF"
    XOR_K4_INTERLEAVED = "XOR_K4_INTERLEAVED"   # +25% overhead (game/voice packets only)
    XOR_K2_INTERLEAVED = "XOR_K2_INTERLEAVED"   # +50% overhead (elevated loss)
    DUPLICATE = "DUPLICATE"                     # +100% overhead (severe loss, small UDP only)


class RouteChoice(str, Enum):
    NATIVE = "NATIVE"
    RELAY = "RELAY"


@dataclass(frozen=True)
class ProfileWeights:
    w_rtt: float
    w_jitter: float
    w_loss: float
    w_bloat: float
    w_bw: float
    min_bw_mbps: float

    def __post_init__(self) -> None:
        total = self.w_rtt + self.w_jitter + self.w_loss + self.w_bloat + self.w_bw
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"Profile weights must sum to 1.0, got {total}")
        if self.min_bw_mbps <= 0:
            raise ValueError("min_bw_mbps must be positive")


PROFILE_WEIGHTS: Dict[TrafficProfile, ProfileWeights] = {
    TrafficProfile.GAME:          ProfileWeights(0.35, 0.30, 0.20, 0.15, 0.00, min_bw_mbps=2.0),
    TrafficProfile.BROWSER:       ProfileWeights(0.20, 0.15, 0.15, 0.15, 0.35, min_bw_mbps=5.0),
    TrafficProfile.DOWNLOAD:      ProfileWeights(0.10, 0.10, 0.15, 0.25, 0.40, min_bw_mbps=25.0),
    TrafficProfile.STREAMING:     ProfileWeights(0.15, 0.25, 0.15, 0.20, 0.25, min_bw_mbps=15.0),
    TrafficProfile.SOCIAL:        ProfileWeights(0.20, 0.20, 0.20, 0.20, 0.20, min_bw_mbps=5.0),
    TrafficProfile.SAFE_BALANCED: ProfileWeights(0.30, 0.25, 0.20, 0.20, 0.05, min_bw_mbps=5.0),
}


# ============================================================================
# Formula #2: Scaled Bitwise EWMA / Jacobson's Algorithm (RFC 6298)
# ============================================================================

class BitwiseEwmaEstimator:
    """
    Integer-only fixed-point RTT & jitter estimator modeled after Linux kernel
    tcp_rtt_estimator / Van Jacobson (1988) / RFC 6298.

    Internal state uses microseconds scaled by powers of two:
      - srtt_scaled   = SRTT_us   << 3   (alpha = 1/8 = 2^-3)
      - rttvar_scaled = RTTVAR_us << 2   (beta  = 1/4 = 2^-2)

    Scaling BEFORE shifting prevents truncation lockup on small RTT deltas.
    """

    MAX_VALID_RTT_US = 30_000_000  # 30 seconds upper sanity bound

    def __init__(self) -> None:
        self._initialized: bool = False
        self._srtt_scaled: int = 0
        self._rttvar_scaled: int = 0
        self._min_rtt_us: Optional[int] = None
        self._last_sample_ts_ms: Optional[int] = None
        self._sample_count: int = 0

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def sample_count(self) -> int:
        return self._sample_count

    def reset(self) -> None:
        self._initialized = False
        self._srtt_scaled = 0
        self._rttvar_scaled = 0
        self._min_rtt_us = None
        self._last_sample_ts_ms = None
        self._sample_count = 0

    def reset_baseline(self, new_min_rtt_ms: Optional[float] = None) -> None:
        """Reset idle baseline after an explicit route or network-interface switch."""
        if new_min_rtt_ms is not None and math.isfinite(new_min_rtt_ms) and new_min_rtt_ms > 0:
            self._min_rtt_us = max(1, int(round(new_min_rtt_ms * 1000.0)))
        else:
            self._min_rtt_us = None

    def update(self, rtt_ms: float, timestamp_ms: int) -> bool:
        """
        Ingest a new RTT measurement in milliseconds.
        Returns True if accepted, False if rejected as invalid/out-of-range.
        """
        if not math.isfinite(rtt_ms) or rtt_ms <= 0.0:
            return False
        rtt_us = int(round(rtt_ms * 1000.0))
        if rtt_us <= 0 or rtt_us > self.MAX_VALID_RTT_US:
            return False
        if self._last_sample_ts_ms is not None and timestamp_ms < self._last_sample_ts_ms:
            return False  # Reject out-of-order timestamp

        if self._min_rtt_us is None or rtt_us < self._min_rtt_us:
            self._min_rtt_us = rtt_us

        if not self._initialized:
            # RFC 6298 initialization: SRTT <- R, RTTVAR <- R/2
            self._srtt_scaled = rtt_us << 3
            self._rttvar_scaled = max(1, rtt_us >> 1) << 2
            self._initialized = True
        else:
            # Jacobson scaled bitwise update (zero floating-point ops)
            err = rtt_us - (self._srtt_scaled >> 3)
            self._srtt_scaled += err
            abs_err = -err if err < 0 else err
            self._rttvar_scaled += abs_err - (self._rttvar_scaled >> 2)

        self._last_sample_ts_ms = timestamp_ms
        self._sample_count += 1
        return True

    def is_stale(self, now_ms: int, max_age_ms: int = 10_000) -> bool:
        if not self._initialized or self._last_sample_ts_ms is None:
            return True
        return (now_ms - self._last_sample_ts_ms) > max_age_ms

    @property
    def srtt_ms(self) -> Optional[float]:
        if not self._initialized:
            return None
        return (self._srtt_scaled / 8.0) / 1000.0

    @property
    def jitter_ms(self) -> Optional[float]:
        if not self._initialized:
            return None
        return (self._rttvar_scaled / 4.0) / 1000.0

    @property
    def rto_ms(self) -> Optional[float]:
        """Retransmission Timeout = SRTT + 4 * RTTVAR (RFC 6298, without 1s TCP floor)."""
        if not self._initialized:
            return None
        rto_us = (self._srtt_scaled >> 3) + self._rttvar_scaled
        return rto_us / 1000.0

    @property
    def min_rtt_ms(self) -> Optional[float]:
        if self._min_rtt_us is None:
            return None
        return self._min_rtt_us / 1000.0

    @property
    def bufferbloat_ms(self) -> Optional[float]:
        if not self._initialized or self._min_rtt_us is None:
            return None
        srtt_us = self._srtt_scaled >> 3
        bloat_us = srtt_us - self._min_rtt_us
        return max(0.0, bloat_us / 1000.0)


# ============================================================================
# Formula #1: Linear Cost Function + Hard Veto Guardrails + Hysteresis
# ============================================================================

@dataclass(frozen=True)
class ScoreResult:
    score_q: float
    cost_c: float
    confidence: float
    veto_reasons: Tuple[str, ...]
    components: Dict[str, float]


class LinearCostScorer:
    """
    Composite linear routing/quality cost model inspired by EIGRP/SD-WAN metrics,
    paired with non-compensatory Hard Veto guardrails so fatal impairments
    (e.g. 10% packet loss in Game profile) cannot be masked by low RTT.
    """

    RTT_SCALE_MS = 200.0
    JITTER_SCALE_MS = 50.0
    LOSS_SCALE_PCT = 10.0
    BLOAT_SCALE_MS = 300.0

    @classmethod
    def evaluate(
        cls,
        srtt_ms: float,
        jitter_ms: float,
        loss_pct: float,
        bufferbloat_ms: float,
        bandwidth_mbps: Optional[float],
        profile: TrafficProfile,
        sample_count: int = 20,
    ) -> ScoreResult:
        w = PROFILE_WEIGHTS[profile]

        r_norm = min(max(srtt_ms, 0.0) / cls.RTT_SCALE_MS, 1.0)
        j_norm = min(max(jitter_ms, 0.0) / cls.JITTER_SCALE_MS, 1.0)
        p_norm = min(max(loss_pct, 0.0) / cls.LOSS_SCALE_PCT, 1.0)
        b_norm = min(max(bufferbloat_ms, 0.0) / cls.BLOAT_SCALE_MS, 1.0)

        confidence = min(1.0, max(0.0, sample_count / 10.0))
        if bandwidth_mbps is None:
            # Missing bandwidth is never treated as 0 Mbps; keep neutral penalty and reduce confidence
            w_norm = 0.0
            confidence *= 0.8
        else:
            w_norm = min(1.0, max(0.0, 1.0 - (max(bandwidth_mbps, 0.0) / w.min_bw_mbps)))

        cost_c = (
            w.w_rtt * r_norm
            + w.w_jitter * j_norm
            + w.w_loss * p_norm
            + w.w_bloat * b_norm
            + w.w_bw * w_norm
        )
        score_q = 100.0 * (1.0 - cost_c)

        # Hard Veto Guardrails (prevents linear compensation trap)
        vetoes: List[str] = []
        if profile == TrafficProfile.GAME:
            if loss_pct >= 5.0:
                score_q = min(score_q, 45.0)
                vetoes.append("VETO_GAME_CRITICAL_LOSS")
            if bufferbloat_ms >= 50.0:
                score_q = min(score_q, 49.0)
                vetoes.append("VETO_GAME_BUFFERBLOAT")
            if bandwidth_mbps is not None and bandwidth_mbps < w.min_bw_mbps:
                score_q = min(score_q, 45.0)
                vetoes.append("VETO_GAME_BELOW_MIN_BW")
        elif profile == TrafficProfile.STREAMING:
            if bandwidth_mbps is not None and bandwidth_mbps < (w.min_bw_mbps * 0.4):
                score_q = min(score_q, 45.0)
                vetoes.append("VETO_STREAMING_STARVED")
            if loss_pct >= 5.0:
                score_q = min(score_q, 49.0)
                vetoes.append("VETO_STREAMING_LOSS")

        return ScoreResult(
            score_q=round(score_q, 2),
            cost_c=round(cost_c, 4),
            confidence=round(confidence, 2),
            veto_reasons=tuple(vetoes),
            components={
                "R": round(r_norm, 4),
                "J": round(j_norm, 4),
                "P": round(p_norm, 4),
                "B_n": round(b_norm, 4),
                "W": round(w_norm, 4),
            },
        )


class ColorStateMachine:
    """
    Anti-flicker status color engine using EWMA score smoothing, asymmetric
    hysteresis bands, minimum dwell time, and explicit UNKNOWN on stale input.
    """

    def __init__(self, min_dwell_ms: int = 2000, ewma_alpha: float = 0.35) -> None:
        self._min_dwell_ms = min_dwell_ms
        self._alpha = ewma_alpha
        self._smoothed_q: Optional[float] = None
        self._state: QualityState = QualityState.UNKNOWN
        self._last_transition_ms: int = -min_dwell_ms

    @property
    def state(self) -> QualityState:
        return self._state

    @property
    def smoothed_score(self) -> Optional[float]:
        return self._smoothed_q

    def update(self, score_q: Optional[float], now_ms: int, is_stale: bool = False) -> QualityState:
        if is_stale or score_q is None:
            self._state = QualityState.UNKNOWN
            self._smoothed_q = None
            self._last_transition_ms = now_ms
            return self._state

        if self._smoothed_q is None:
            self._smoothed_q = score_q
        else:
            self._smoothed_q = self._alpha * score_q + (1.0 - self._alpha) * self._smoothed_q

        q = self._smoothed_q
        dwell_elapsed = (now_ms - self._last_transition_ms) >= self._min_dwell_ms

        if self._state == QualityState.UNKNOWN:
            target = (
                QualityState.GREEN if q >= 80.0
                else QualityState.YELLOW if q >= 50.0
                else QualityState.RED
            )
            self._state = target
            self._last_transition_ms = now_ms
            return self._state

        target = self._state
        if self._state == QualityState.GREEN:
            if q < 48.0:
                target = QualityState.RED
            elif q < 75.0:
                target = QualityState.YELLOW
        elif self._state == QualityState.YELLOW:
            if q >= 82.0:
                target = QualityState.GREEN
            elif q < 48.0:
                target = QualityState.RED
        elif self._state == QualityState.RED:
            if q >= 82.0:
                target = QualityState.GREEN
            elif q >= 55.0:
                target = QualityState.YELLOW

        # Allow fast downgrade to RED on severe drop; enforce dwell on normal/recovery changes
        severe_drop = (target == QualityState.RED and score_q < 45.0)
        if target != self._state and (dwell_elapsed or severe_drop):
            self._state = target
            self._last_transition_ms = now_ms

        return self._state


# ============================================================================
# Formula #3: Bitwise XOR Parity FEC over GF(2) with Interleaved Stride
# ============================================================================

@dataclass(frozen=True)
class FecFrame:
    """
    Lightweight wire frame for JITER Adaptive XOR FEC (8-byte header + payload).
    Header format: !I H B B (group_id: u32, orig_len: u16, slot_index: u8, flags_and_k: u8)
    """
    group_id: int
    slot_index: int     # 0..k-1 for data packets; k for parity packet
    block_k: int        # Number of data packets per parity group (1..15)
    is_parity: bool
    payload: bytes      # For data: raw payload; for parity: XOR of length-prefixed padded slots


def _xor_buffers(bufs: List[bytes]) -> bytes:
    """Bitwise XOR across equal-length byte buffers (GF(2) addition)."""
    if not bufs:
        return b""
    max_len = max(len(b) for b in bufs)
    acc = bytearray(max_len)
    for b in bufs:
        for i, val in enumerate(b):
            acc[i] ^= val
    return bytes(acc)


def _pack_len_prefixed(payload: bytes) -> bytes:
    return struct.pack("!H", len(payload)) + payload


def _unpack_len_prefixed(framed: bytes) -> bytes:
    if len(framed) < 2:
        raise ValueError("Corrupted FEC recovered buffer: shorter than 2-byte length prefix")
    (orig_len,) = struct.unpack("!H", framed[:2])
    if orig_len > len(framed) - 2:
        raise ValueError(f"Corrupted FEC recovered length {orig_len} > {len(framed) - 2}")
    return framed[2 : 2 + orig_len]


class InterleavedXorFecEncoder:
    """
    Stateful GF(2) XOR Parity Encoder with interleaved groups (`stride`).

    Interleaving spreads consecutive packets across `stride` independent XOR
    groups so a wireless burst drop of up to `stride` consecutive packets leaves
    at most 1 missing packet per group — making all of them 100% recoverable at
    the exact same 1/k bandwidth overhead.
    """

    def __init__(self, block_k: int = 4, stride: int = 4) -> None:
        if not (1 <= block_k <= 15):
            raise ValueError("block_k must be in 1..15")
        if not (1 <= stride <= 16):
            raise ValueError("stride must be in 1..16")
        self.block_k = block_k
        self.stride = stride
        self._next_group_id = 0
        self._active_group_ids: List[int] = [self._alloc_group_id() for _ in range(stride)]
        self._group_slots: List[List[bytes]] = [[] for _ in range(stride)]
        self._cursor = 0

    def _alloc_group_id(self) -> int:
        gid = self._next_group_id
        self._next_group_id = (self._next_group_id + 1) & 0xFFFFFFFF
        return gid

    def encode_packet(self, payload: bytes) -> List[FecFrame]:
        """
        Accept one original UDP payload and emit 1 Data FecFrame immediately
        (zero sender queueing delay!), plus 1 Parity FecFrame whenever the
        assigned interleaved group completes `block_k` packets.
        """
        lane = self._cursor
        self._cursor = (self._cursor + 1) % self.stride

        gid = self._active_group_ids[lane]
        slots = self._group_slots[lane]
        slot_idx = len(slots)

        data_frame = FecFrame(
            group_id=gid,
            slot_index=slot_idx,
            block_k=self.block_k,
            is_parity=False,
            payload=payload,
        )
        slots.append(_pack_len_prefixed(payload))
        out = [data_frame]

        if len(slots) == self.block_k:
            parity_payload = _xor_buffers(slots)
            out.append(
                FecFrame(
                    group_id=gid,
                    slot_index=self.block_k,
                    block_k=self.block_k,
                    is_parity=True,
                    payload=parity_payload,
                )
            )
            self._group_slots[lane] = []
            self._active_group_ids[lane] = self._alloc_group_id()

        return out


class InterleavedXorFecDecoder:
    """
    GF(2) XOR Parity Decoder with bounded group memory.
    Immediately forwards arriving data packets (zero extra delay when no loss)
    and instantly reconstructs a single lost data packet per group upon receiving
    the remaining k-1 data packets + parity packet.
    """

    def __init__(self, max_tracked_groups: int = 64) -> None:
        self._max_groups = max_tracked_groups
        self._groups: Dict[int, Dict[str, object]] = {}
        self.recovered_count: int = 0
        self.unrecoverable_groups: int = 0

    def _evict_oldest_if_needed(self) -> None:
        while len(self._groups) > self._max_groups:
            oldest_gid = next(iter(self._groups))
            grp = self._groups.pop(oldest_gid)
            data_map: Dict[int, bytes] = grp["data"]  # type: ignore[assignment]
            k: int = grp["k"]  # type: ignore[assignment]
            if len(data_map) < k:
                self.unrecoverable_groups += 1

    def receive(self, frame: FecFrame) -> List[Tuple[int, int, bytes]]:
        """
        Process an incoming FecFrame.
        Returns a list of delivered/recovered `(group_id, slot_index, original_payload)` tuples.
        """
        gid = frame.group_id
        grp = self._groups.get(gid)
        if grp is None:
            grp = {"k": frame.block_k, "data": {}, "parity": None, "done": False}
            self._groups[gid] = grp
            self._evict_oldest_if_needed()

        if grp["done"]:
            return []

        delivered: List[Tuple[int, int, bytes]] = []
        data_map: Dict[int, bytes] = grp["data"]  # type: ignore[assignment]
        k: int = grp["k"]  # type: ignore[assignment]

        if not frame.is_parity:
            if frame.slot_index not in data_map:
                data_map[frame.slot_index] = _pack_len_prefixed(frame.payload)
                delivered.append((gid, frame.slot_index, frame.payload))
        else:
            grp["parity"] = frame.payload

        # Complete without needing recovery
        if len(data_map) == k:
            grp["done"] = True
            return delivered

        # Exactly 1 data packet missing and parity is present -> INSTANT GF(2) RECOVERY!
        parity_buf: Optional[bytes] = grp["parity"]  # type: ignore[assignment]
        if parity_buf is not None and len(data_map) == (k - 1):
            missing_slots = [idx for idx in range(k) if idx not in data_map]
            missing_idx = missing_slots[0]
            recovered_framed = _xor_buffers(list(data_map.values()) + [parity_buf])
            recovered_payload = _unpack_len_prefixed(recovered_framed)
            data_map[missing_idx] = recovered_framed
            grp["done"] = True
            self.recovered_count += 1
            delivered.append((gid, missing_idx, recovered_payload))

        return delivered


# ============================================================================
# Closed-Loop Adaptive Controller (#2 -> #1 -> #3 + Pacer + Route Selector)
# ============================================================================

@dataclass(frozen=True)
class ControlDecision:
    quality_score: Optional[float]
    quality_state: QualityState
    fec_mode: FecMode
    bg_pacer_ratio: float
    selected_route: RouteChoice
    confidence: float
    reason_codes: Tuple[str, ...]


class AdaptiveController:
    """
    Coordinates Formula #2 (EWMA), Formula #1 (Linear Cost + Hysteresis),
    and Formula #3 (Adaptive XOR FEC) plus Anti-Bufferbloat Background Pacing
    and Relay Route Selection with cooldown & hysteresis.
    """

    def __init__(
        self,
        route_hysteresis_pts: float = 10.0,
        route_cooldown_ms: int = 5000,
    ) -> None:
        self.color_engine = ColorStateMachine()
        self.fec_mode: FecMode = FecMode.OFF
        self.bg_pacer_ratio: float = 1.0
        self.selected_route: RouteChoice = RouteChoice.NATIVE
        self._route_hysteresis_pts = route_hysteresis_pts
        self._route_cooldown_ms = route_cooldown_ms
        self._last_route_switch_ms: int = -route_cooldown_ms

    def step(
        self,
        now_ms: int,
        profile: TrafficProfile,
        ewma: BitwiseEwmaEstimator,
        loss_pct: float,
        bandwidth_mbps: Optional[float],
        alternate_route_metrics: Optional[Tuple[float, float, float, float]] = None,
    ) -> ControlDecision:
        """
        Evaluate current active-route state and emit policy actions.
        `alternate_route_metrics` is optional `(srtt_ms, jitter_ms, loss_pct, bloat_ms)`
        for the non-active candidate route (RELAY when on NATIVE; NATIVE probe when on RELAY).
        """
        reasons: List[str] = []

        if ewma.is_stale(now_ms):
            q_state = self.color_engine.update(None, now_ms, is_stale=True)
            self.fec_mode = FecMode.OFF
            self.bg_pacer_ratio = 1.0
            return ControlDecision(
                quality_score=None,
                quality_state=q_state,
                fec_mode=self.fec_mode,
                bg_pacer_ratio=self.bg_pacer_ratio,
                selected_route=self.selected_route,
                confidence=0.0,
                reason_codes=("STALE_OR_MISSING_SAMPLES",),
            )

        assert ewma.srtt_ms is not None
        assert ewma.jitter_ms is not None
        assert ewma.bufferbloat_ms is not None

        score = LinearCostScorer.evaluate(
            srtt_ms=ewma.srtt_ms,
            jitter_ms=ewma.jitter_ms,
            loss_pct=loss_pct,
            bufferbloat_ms=ewma.bufferbloat_ms,
            bandwidth_mbps=bandwidth_mbps,
            profile=profile,
            sample_count=ewma.sample_count,
        )
        reasons.extend(score.veto_reasons)
        q_state = self.color_engine.update(score.score_q, now_ms, is_stale=False)

        # 1) Anti-Bufferbloat Background Pacer
        if profile in (TrafficProfile.GAME, TrafficProfile.STREAMING):
            if ewma.bufferbloat_ms > 5.0 or score.score_q < 85.0:
                self.bg_pacer_ratio = max(0.15, round(self.bg_pacer_ratio * 0.65, 3))
                reasons.append("PACER_THROTTLE_BG")
            else:
                self.bg_pacer_ratio = min(0.55, round(self.bg_pacer_ratio + 0.03, 3))
                reasons.append("PACER_RESERVE_HEADROOM")
        else:
            self.bg_pacer_ratio = 1.0
            reasons.append("PACER_FULL_THROUGHPUT")

        # 2) Adaptive Formula #3 (XOR FEC) — ONLY for latency-sensitive profiles
        if profile == TrafficProfile.GAME:
            if loss_pct >= 6.0:
                self.fec_mode = FecMode.XOR_K2_INTERLEAVED
                reasons.append("FEC_ELEVATED_K2")
            elif loss_pct >= 1.0 or ewma.jitter_ms >= 8.0:
                self.fec_mode = FecMode.XOR_K4_INTERLEAVED
                reasons.append("FEC_ACTIVE_K4")
            elif loss_pct < 0.3 and ewma.jitter_ms < 4.0:
                self.fec_mode = FecMode.OFF
                reasons.append("FEC_STANDBY_CLEAN_LINK")
        else:
            self.fec_mode = FecMode.OFF

        # 3) Route Intelligence (Active vs Alternate Route with Hysteresis & Cooldown)
        if alternate_route_metrics is not None and (now_ms - self._last_route_switch_ms) >= self._route_cooldown_ms:
            a_rtt, a_jit, a_loss, a_bloat = alternate_route_metrics
            alt_score = LinearCostScorer.evaluate(
                srtt_ms=a_rtt,
                jitter_ms=a_jit,
                loss_pct=a_loss,
                bufferbloat_ms=a_bloat,
                bandwidth_mbps=bandwidth_mbps,
                profile=profile,
                sample_count=ewma.sample_count,
            )
            if alt_score.score_q >= (score.score_q + self._route_hysteresis_pts):
                if self.selected_route == RouteChoice.NATIVE:
                    self.selected_route = RouteChoice.RELAY
                    reasons.append("ROUTE_SWITCH_TO_RELAY")
                else:
                    self.selected_route = RouteChoice.NATIVE
                    reasons.append("ROUTE_SWITCH_TO_NATIVE")
                self._last_route_switch_ms = now_ms

        return ControlDecision(
            quality_score=score.score_q,
            quality_state=q_state,
            fec_mode=self.fec_mode,
            bg_pacer_ratio=self.bg_pacer_ratio,
            selected_route=self.selected_route,
            confidence=score.confidence,
            reason_codes=tuple(reasons),
        )
