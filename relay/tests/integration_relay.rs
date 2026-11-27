use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use jiter_math::fec::InterleavedXorFecEncoder;
use jiter_relay::protocol::{
    pacer_ratio_to_q8, HelloAckPayload, HelloReqPayload, MsgType, PolicySyncPayload,
    ProbeReqPayload, ProbeRespPayload, TrafficTier, WireHeader, FLAG_FEC_PARITY, FLAG_GOODBYE,
    WIRE_HEADER_BYTES, WIRE_VERSION,
};
use jiter_relay::scheduler::DownstreamScheduler;
use jiter_relay::server::{RelayConfig, RelayMode, RelayServer};

#[test]
fn wire_header_matches_c_specification_golden_bytes() {
    let hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::DataFec,
        traffic_tier: TrafficTier::Game,
        flags: FLAG_FEC_PARITY,
        session_id: 0x1122_3344,
        sequence: 42,
        payload_len: 128,
        pacer_q8: pacer_ratio_to_q8(0.35),
        fec_mode: 2,
    };

    let packed = hdr.pack().expect("pack golden wire header");
    let expected: [u8; WIRE_HEADER_BYTES] = [
        0x4A, 0x54, 0x16, 0x02, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x80, 0x59,
        0x02,
    ];
    assert_eq!(packed, expected);

    let unpacked = WireHeader::unpack(&packed).expect("unpack golden wire header");
    assert_eq!(unpacked, hdr);
}

#[test]
fn handshake_probe_and_goodbye_lifecycle_over_real_udp() {
    let cfg = RelayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        region_tag: "JKT-1".to_string(),
        mode: RelayMode::Echo,
        ..RelayConfig::default()
    };

    let mut server = RelayServer::bind(cfg).expect("bind relay");
    let relay_addr = server.local_addr().expect("local addr");
    let counters = server.counters();
    let stop = server.stop_handle();

    let handle = thread::spawn(move || {
        let _ = server.run();
    });

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");

    let session_id = 0xCAFE_BABEu32;

    // 1. HELLO_REQ -> HELLO_ACK
    let hello_payload = HelloReqPayload {
        profile_id: 0, // Game
        routing_mode: 1,
        fec_policy: 0,
        reserved: 0,
        mtu: 1280,
        link_hint_mbps_x10: 350, // 35.0 Mbps
    }
    .pack();
    let hello_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::HelloReq,
        traffic_tier: TrafficTier::Game,
        flags: 0,
        session_id,
        sequence: 1,
        payload_len: hello_payload.len() as u16,
        pacer_q8: 255,
        fec_mode: 2,
    };
    client
        .send_to(&hello_hdr.frame_bytes(&hello_payload).unwrap(), relay_addr)
        .expect("send hello");

    let mut buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut buf).expect("recv hello ack");
    let ack_hdr = WireHeader::unpack(&buf[..n]).expect("unpack ack hdr");
    assert_eq!(ack_hdr.msg_type, MsgType::HelloAck);
    assert_eq!(ack_hdr.session_id, session_id);
    let ack = HelloAckPayload::unpack(&buf[WIRE_HEADER_BYTES..n]).expect("unpack ack");
    assert_eq!(ack.region_str(), "JKT-1");
    assert_eq!(ack.accepted_mtu, 1280);

    // 2. PROBE_REQ -> PROBE_RESP
    let tx_us = 123_456_789u64;
    let probe_payload = ProbeReqPayload {
        client_tx_us: tx_us,
        profile_id: 0,
        reserved: 0,
    }
    .pack();
    let probe_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::ProbeReq,
        traffic_tier: TrafficTier::Game,
        flags: 0,
        session_id,
        sequence: 2,
        payload_len: probe_payload.len() as u16,
        pacer_q8: pacer_ratio_to_q8(0.35),
        fec_mode: 2,
    };
    client
        .send_to(&probe_hdr.frame_bytes(&probe_payload).unwrap(), relay_addr)
        .expect("send probe");

    let (n2, _) = client.recv_from(&mut buf).expect("recv probe resp");
    let resp_hdr = WireHeader::unpack(&buf[..n2]).expect("unpack probe resp hdr");
    assert_eq!(resp_hdr.msg_type, MsgType::ProbeResp);
    let resp = ProbeRespPayload::unpack(&buf[WIRE_HEADER_BYTES..n2]).expect("unpack probe resp");
    assert_eq!(resp.echo_tx_us, tx_us);
    assert_eq!(resp.relay_pacer_q8 as u8, pacer_ratio_to_q8(0.35));
    assert_eq!(counters.snapshot().active_sessions, 1);

    // 3. GOODBYE -> instant RAM wipe
    let bye_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::Control,
        traffic_tier: TrafficTier::Game,
        flags: FLAG_GOODBYE,
        session_id,
        sequence: 3,
        payload_len: 0,
        pacer_q8: 255,
        fec_mode: 0,
    };
    client
        .send_to(&bye_hdr.frame_bytes(&[]).unwrap(), relay_addr)
        .expect("send goodbye");

    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && counters.snapshot().active_sessions > 0 {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(counters.snapshot().active_sessions, 0);
    assert_eq!(counters.snapshot().goodbyes_served, 1);

    stop.store(true, Ordering::Relaxed);
    handle.join().expect("join server");
}

#[test]
fn uplink_xor_fec_recovers_dropped_game_packet_over_udp() {
    let cfg = RelayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        region_tag: "SG-1".to_string(),
        mode: RelayMode::Echo,
        ..RelayConfig::default()
    };

    let mut server = RelayServer::bind(cfg).expect("bind relay");
    let relay_addr = server.local_addr().expect("local addr");
    let counters = server.counters();
    let stop = server.stop_handle();

    let handle = thread::spawn(move || {
        let _ = server.run();
    });

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");

    let session_id = 0x0042_1337u32;

    // Tell relay we want Game profile + XOR k=2 uplink decoding, plain echo back for clean payload check
    let sync = PolicySyncPayload {
        profile_id: 0,
        fec_mode: 0, // downlink OFF so echoed payloads arrive as DataPlain directly
        pacer_q8: pacer_ratio_to_q8(0.25),
        reserved: 0,
        link_mbps_x10: 300,
        reserved2: 0,
    }
    .pack();
    let sync_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::PolicySync,
        traffic_tier: TrafficTier::Game,
        flags: 0,
        session_id,
        sequence: 1,
        payload_len: sync.len() as u16,
        pacer_q8: pacer_ratio_to_q8(0.25),
        fec_mode: 0,
    };
    client
        .send_to(&sync_hdr.frame_bytes(&sync).unwrap(), relay_addr)
        .expect("send sync");

    // Encode 2 game packets with XOR FEC k=2 -> emits [DATA0, DATA1, PARITY]
    let mut enc = InterleavedXorFecEncoder::new(2, 1);
    let pkt0 = b"GAME_TICK_001_POS_X120_Y44".to_vec();
    let pkt1 = b"GAME_TICK_002_SHOT_CRIT_99".to_vec();

    let mut fec_frames = Vec::new();
    fec_frames.extend(enc.encode_packet(&pkt0));
    fec_frames.extend(enc.encode_packet(&pkt1));
    assert_eq!(fec_frames.len(), 3);

    // Simulate wireless packet loss: DROP index 1 (pkt1), send only DATA0 and PARITY!
    let mut seq = 2u32;
    for (idx, fr) in fec_frames.iter().enumerate() {
        if idx == 1 {
            seq += 1; // Sequence gap simulates real wireless loss
            continue;
        }
        let wire_fec = fr.to_wire_bytes();
        let hdr = WireHeader {
            version: WIRE_VERSION,
            msg_type: MsgType::DataFec,
            traffic_tier: TrafficTier::Game,
            flags: if fr.is_parity { FLAG_FEC_PARITY } else { 0 },
            session_id,
            sequence: seq,
            payload_len: wire_fec.len() as u16,
            pacer_q8: pacer_ratio_to_q8(0.25),
            fec_mode: 0,
        };
        client
            .send_to(&hdr.frame_bytes(&wire_fec).unwrap(), relay_addr)
            .expect("send fec frame");
        seq += 1;
    }

    // Receive both echoed packets from relay — pkt1 MUST be recovered bit-exact via GF(2) XOR!
    let mut received: Vec<Vec<u8>> = Vec::new();
    let mut buf = [0u8; 2048];
    for _ in 0..2 {
        let (n, _) = client.recv_from(&mut buf).expect("recv echoed data");
        let hdr = WireHeader::unpack(&buf[..n]).expect("unpack");
        assert_eq!(hdr.msg_type, MsgType::DataPlain);
        let p = buf[WIRE_HEADER_BYTES..WIRE_HEADER_BYTES + hdr.payload_len as usize].to_vec();
        received.push(p);
    }

    assert!(received.contains(&pkt0));
    assert!(received.contains(&pkt1));
    assert_eq!(counters.snapshot().fec_recovered_packets, 1);

    stop.store(true, Ordering::Relaxed);
    handle.join().expect("join server");
}

#[test]
fn downstream_scheduler_prioritizes_game_and_paces_background() {
    let mut sched = DownstreamScheduler::new(16, 16, 16);
    sched.configure_pacer(0.20, 10.0);

    assert!(sched.enqueue(TrafficTier::Background, vec![0xBB; 1300], 1_000));
    assert!(sched.enqueue(TrafficTier::Background, vec![0xBB; 1300], 1_000));
    assert!(sched.enqueue(TrafficTier::Background, vec![0xBB; 1300], 1_000));
    assert!(sched.enqueue(TrafficTier::Background, vec![0xBB; 1300], 1_000));
    assert!(sched.enqueue(TrafficTier::Streaming, vec![0x55; 1200], 1_000));
    assert!(sched.enqueue(TrafficTier::Game, vec![0x11; 96], 1_000));

    let first = sched.dequeue(1_000).expect("game first");
    assert_eq!(first.tier, TrafficTier::Game);

    let second = sched.dequeue(1_000).expect("streaming second");
    assert_eq!(second.tier, TrafficTier::Streaming);

    let mut bg_popped = 0usize;
    while let Some(p) = sched.dequeue(1_000) {
        assert_eq!(p.tier, TrafficTier::Background);
        bg_popped += 1;
    }
    assert!(bg_popped < 4);
    assert!(sched.stats().bg_pacer_deferrals >= 1);

    // After 25ms, tokens refill and release paced background traffic
    let later = sched.dequeue(1_025).expect("refilled bg");
    assert_eq!(later.tier, TrafficTier::Background);
}
