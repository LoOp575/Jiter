use std::net::UdpSocket;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use jiter_math::fec::InterleavedXorFecEncoder;
use jiter_relay::crypto::{
    compute_hello_ack_tag, compute_hello_req_tag, constant_time_eq_16, derive_psk_key,
    derive_session_keys, random_nonce_16, EphemeralP256KeyPair, ReplayWindow, SessionCipher,
    AEAD_TAG_BYTES,
};
use jiter_relay::protocol::{
    pacer_ratio_to_q8, EncryptedHelloAckPayload, EncryptedHelloReqPayload, HelloAckPayload,
    HelloReqPayload, MsgType, PolicySyncPayload, ProbeReqPayload, ProbeRespPayload, TrafficTier,
    WireHeader, FLAG_ENCRYPTED, FLAG_FEC_PARITY, FLAG_GOODBYE, RELAY_CAP_AEAD_CHACHA20,
    WIRE_HEADER_BYTES, WIRE_VERSION,
};
use jiter_relay::scheduler::DownstreamScheduler;
use jiter_relay::server::{RelayConfig, RelayMode, RelayServer};
use jiter_relay::tun::{parse_ipv4_summary, TunIpPool};

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

#[test]
fn stage4_crypto_golden_vector_and_replay_window() {
    // Deterministic cross-language golden check shared with Android Kotlin JiterEngineTest
    let psk_key = derive_psk_key("jiter-golden-psk-2026");
    let expected_psk_key: [u8; 32] = [
        0x97, 0x16, 0xca, 0xc9, 0x7a, 0x20, 0x45, 0x14, 0x28, 0xec, 0x08, 0x51, 0xa9, 0xcf, 0x62,
        0x92, 0xa7, 0x3e, 0xb7, 0xbe, 0x98, 0x29, 0x35, 0xdf, 0x53, 0xa6, 0x42, 0x05, 0xf0, 0xa3,
        0x6c, 0x96,
    ];
    assert_eq!(psk_key, expected_psk_key);

    let ecdh_shared = [0x42u8; 32];
    let c_nonce = [0x11u8; 16];
    let s_nonce = [0x22u8; 16];
    let session_id = 0x1122_3344u32;

    let keys = derive_session_keys(&ecdh_shared, &psk_key, &c_nonce, &s_nonce, session_id);
    assert_eq!(keys.c2s_iv, [0x82, 0x66, 0x92, 0x4c]);
    assert_eq!(keys.s2c_iv, [0xe6, 0x4d, 0x89, 0xea]);

    let client_cipher = SessionCipher::for_client(&keys);
    let mut server_cipher = SessionCipher::for_server(&keys);

    let aad_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::DataPlain,
        traffic_tier: TrafficTier::Game,
        flags: FLAG_ENCRYPTED,
        session_id,
        sequence: 7,
        payload_len: (16 + AEAD_TAG_BYTES) as u16,
        pacer_q8: 89,
        fec_mode: 2,
    }
    .pack()
    .unwrap();

    let plaintext = b"JITER_AEAD_CHECK";
    let ct = client_cipher
        .encrypt(session_id, 7, &aad_hdr, plaintext)
        .expect("encrypt");
    let expected_ct: [u8; 32] = [
        0x63, 0x52, 0xf7, 0x03, 0x70, 0x9c, 0xe9, 0x3a, 0x88, 0x53, 0xee, 0x58, 0x04, 0xa3, 0x1a,
        0xc1, 0x6f, 0x9e, 0x11, 0x2a, 0xf1, 0x23, 0x0e, 0x8a, 0xa3, 0x53, 0xa3, 0xf6, 0xc0, 0xe2,
        0xd3, 0x61,
    ];
    assert_eq!(ct, expected_ct);

    // Tampered AAD must fail Poly1305 verification
    let mut bad_aad = aad_hdr;
    bad_aad[14] ^= 0x01;
    assert!(server_cipher
        .decrypt_and_check_replay(session_id, 7, &bad_aad, &ct)
        .is_none());

    // Valid AAD decrypts bit-exact
    let pt = server_cipher
        .decrypt_and_check_replay(session_id, 7, &aad_hdr, &ct)
        .expect("decrypt");
    assert_eq!(pt, plaintext);

    // Replayed sequence 7 must be rejected!
    assert!(server_cipher
        .decrypt_and_check_replay(session_id, 7, &aad_hdr, &ct)
        .is_none());

    // Direct ReplayWindow edge cases
    let mut rw = ReplayWindow::new();
    assert!(!rw.would_accept(0));
    assert!(rw.would_accept(10));
    rw.mark_accepted(10);
    assert!(!rw.would_accept(10));
    assert!(rw.would_accept(5)); // out-of-order within 64 window
    rw.mark_accepted(5);
    assert!(!rw.would_accept(5));
    rw.mark_accepted(100);
    assert!(!rw.would_accept(36)); // 100 - 36 == 64 -> too old
    assert!(rw.would_accept(37)); // 100 - 37 == 63 -> still inside window
}

#[test]
fn encrypted_ecdhe_p256_handshake_probe_fec_and_replay_drop_over_udp() {
    let psk = "super-secret-jiter-jkt-key";
    let psk_key = derive_psk_key(psk);

    let cfg = RelayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        region_tag: "JKT-AEAD".to_string(),
        mode: RelayMode::Echo,
        psk: Some(psk.to_string()),
        ..RelayConfig::default()
    };

    let mut server = RelayServer::bind(cfg).expect("bind encrypted relay");
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

    let session_id = 0x51A6_E401u32;

    // 1. Wrong PSK attempt must be dropped cleanly
    let bad_kp = EphemeralP256KeyPair::generate();
    let bad_nonce = random_nonce_16();
    let bad_req = EncryptedHelloReqPayload {
        base: HelloReqPayload {
            profile_id: 0,
            routing_mode: 0,
            fec_policy: 0,
            reserved: 0,
            mtu: 1280,
            link_hint_mbps_x10: 500,
        },
        client_pub: bad_kp.public_bytes(),
        client_nonce: bad_nonce,
        auth_tag: [0xFFu8; 16], // wrong tag!
    };
    let bad_bytes = bad_req.pack();
    let bad_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::HelloReq,
        traffic_tier: TrafficTier::Game,
        flags: FLAG_ENCRYPTED,
        session_id,
        sequence: 1,
        payload_len: bad_bytes.len() as u16,
        pacer_q8: 255,
        fec_mode: 0,
    };
    client
        .send_to(&bad_hdr.frame_bytes(&bad_bytes).unwrap(), relay_addr)
        .expect("send bad hello");

    let deadline_bad = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline_bad && counters.snapshot().auth_or_replay_drops == 0 {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(counters.snapshot().auth_or_replay_drops >= 1);

    // 2. Valid ECDHE P-256 + PSK HELLO_REQ -> HELLO_ACK
    let client_kp = EphemeralP256KeyPair::generate();
    let client_nonce = random_nonce_16();
    let req = EncryptedHelloReqPayload {
        base: HelloReqPayload {
            profile_id: 0,
            routing_mode: 0,
            fec_policy: 0,
            reserved: 0,
            mtu: 1280,
            link_hint_mbps_x10: 500,
        },
        client_pub: client_kp.public_bytes(),
        client_nonce,
        auth_tag: [0u8; 16],
    };
    let mut req_bytes = req.pack();
    let client_tag = compute_hello_req_tag(
        &psk_key,
        session_id,
        &req_bytes[..EncryptedHelloReqPayload::BODY_BEFORE_TAG],
    );
    req_bytes[EncryptedHelloReqPayload::BODY_BEFORE_TAG..].copy_from_slice(&client_tag);

    let hello_hdr = WireHeader {
        version: WIRE_VERSION,
        msg_type: MsgType::HelloReq,
        traffic_tier: TrafficTier::Game,
        flags: FLAG_ENCRYPTED,
        session_id,
        sequence: 1,
        payload_len: req_bytes.len() as u16,
        pacer_q8: 255,
        fec_mode: 0,
    };
    client
        .send_to(&hello_hdr.frame_bytes(&req_bytes).unwrap(), relay_addr)
        .expect("send valid encrypted hello");

    let mut buf = [0u8; 2048];
    let (n, _) = client.recv_from(&mut buf).expect("recv encrypted ack");
    let ack_hdr = WireHeader::unpack(&buf[..n]).expect("unpack ack hdr");
    assert_eq!(ack_hdr.msg_type, MsgType::HelloAck);
    assert_ne!(ack_hdr.flags & FLAG_ENCRYPTED, 0);
    let ack_raw = &buf[WIRE_HEADER_BYTES..n];
    let ack = EncryptedHelloAckPayload::unpack(ack_raw).expect("unpack encrypted ack");
    assert_eq!(ack.base.region_str(), "JKT-AEAD");
    assert_eq!(ack.assigned_ipv4, [10, 77, 0, 2]);
    assert_ne!(ack.base.relay_caps & RELAY_CAP_AEAD_CHACHA20, 0);

    let expected_server_tag = compute_hello_ack_tag(
        &psk_key,
        session_id,
        &client_nonce,
        &ack_raw[..EncryptedHelloAckPayload::BODY_BEFORE_TAG],
    );
    assert!(constant_time_eq_16(&expected_server_tag, &ack.auth_tag));

    let shared = client_kp
        .diffie_hellman(&ack.server_pub)
        .expect("client ecdh");
    let keys = derive_session_keys(&shared, &psk_key, &client_nonce, &ack.server_nonce, session_id);
    let mut client_cipher = SessionCipher::for_client(&keys);

    // Helper to build encrypted client frame
    let encrypt_client_frame = |cipher: &SessionCipher,
                                msg_type: MsgType,
                                tier: TrafficTier,
                                extra_flags: u8,
                                seq: u32,
                                plain: &[u8]|
     -> Vec<u8> {
        let hdr = WireHeader {
            version: WIRE_VERSION,
            msg_type,
            traffic_tier: tier,
            flags: extra_flags | FLAG_ENCRYPTED,
            session_id,
            sequence: seq,
            payload_len: (plain.len() + AEAD_TAG_BYTES) as u16,
            pacer_q8: pacer_ratio_to_q8(0.30),
            fec_mode: 0,
        };
        let aad = hdr.pack().unwrap();
        let ct = cipher.encrypt(session_id, seq, &aad, plain).unwrap();
        let mut frame = Vec::with_capacity(WIRE_HEADER_BYTES + ct.len());
        frame.extend_from_slice(&aad);
        frame.extend_from_slice(&ct);
        frame
    };

    // 3. Encrypted PROBE_REQ -> Encrypted PROBE_RESP
    let probe_plain = ProbeReqPayload {
        client_tx_us: 999_888_777,
        profile_id: 0,
        reserved: 0,
    }
    .pack();
    let probe_frame = encrypt_client_frame(
        &client_cipher,
        MsgType::ProbeReq,
        TrafficTier::Game,
        0,
        2,
        &probe_plain,
    );
    client.send_to(&probe_frame, relay_addr).expect("send enc probe");

    let (pn, _) = client.recv_from(&mut buf).expect("recv enc probe resp");
    let phdr = WireHeader::unpack(&buf[..pn]).expect("unpack probe resp hdr");
    assert_eq!(phdr.msg_type, MsgType::ProbeResp);
    assert_ne!(phdr.flags & FLAG_ENCRYPTED, 0);
    let pplain = client_cipher
        .decrypt_and_check_replay(
            phdr.session_id,
            phdr.sequence,
            &buf[..WIRE_HEADER_BYTES],
            &buf[WIRE_HEADER_BYTES..pn],
        )
        .expect("decrypt probe resp");
    let presp = ProbeRespPayload::unpack(&pplain).expect("unpack probe resp");
    assert_eq!(presp.echo_tx_us, 999_888_777);

    // 4. Replay exact same probe frame -> MUST be rejected by Anti-Replay Window!
    let drops_before = counters.snapshot().auth_or_replay_drops;
    client
        .send_to(&probe_frame, relay_addr)
        .expect("send replay probe");
    let deadline_rep = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline_rep && counters.snapshot().auth_or_replay_drops <= drops_before
    {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(counters.snapshot().auth_or_replay_drops > drops_before);

    // 5. Encrypted XOR FEC recovery over UDP (drop pkt1, recover bit-exact)
    let mut enc = InterleavedXorFecEncoder::new(2, 1);
    let pkt0 = b"ENCRYPTED_GAME_FRAME_0".to_vec();
    let pkt1 = b"ENCRYPTED_GAME_FRAME_1".to_vec();
    let mut frames = Vec::new();
    frames.extend(enc.encode_packet(&pkt0));
    frames.extend(enc.encode_packet(&pkt1));

    let mut seq = 10u32;
    for (idx, fr) in frames.iter().enumerate() {
        if idx == 1 {
            seq += 1;
            continue; // simulated drop
        }
        let fbytes = fr.to_wire_bytes();
        let wire = encrypt_client_frame(
            &client_cipher,
            MsgType::DataFec,
            TrafficTier::Game,
            if fr.is_parity { FLAG_FEC_PARITY } else { 0 },
            seq,
            &fbytes,
        );
        client.send_to(&wire, relay_addr).expect("send enc fec");
        seq += 1;
    }

    let mut echoed = Vec::new();
    for _ in 0..2 {
        let (dn, _) = client.recv_from(&mut buf).expect("recv enc echo");
        let dhdr = WireHeader::unpack(&buf[..dn]).expect("unpack");
        assert_eq!(dhdr.msg_type, MsgType::DataPlain);
        assert_ne!(dhdr.flags & FLAG_ENCRYPTED, 0);
        let dplain = client_cipher
            .decrypt_and_check_replay(
                dhdr.session_id,
                dhdr.sequence,
                &buf[..WIRE_HEADER_BYTES],
                &buf[WIRE_HEADER_BYTES..dn],
            )
            .expect("decrypt echoed data");
        echoed.push(dplain);
    }
    assert!(echoed.contains(&pkt0));
    assert!(echoed.contains(&pkt1));
    assert_eq!(counters.snapshot().fec_recovered_packets, 1);

    // 6. Encrypted GOODBYE wipes RAM session cleanly
    let bye_frame = encrypt_client_frame(
        &client_cipher,
        MsgType::Control,
        TrafficTier::Game,
        FLAG_GOODBYE,
        20,
        &[],
    );
    client.send_to(&bye_frame, relay_addr).expect("send enc bye");

    let deadline_bye = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline_bye && counters.snapshot().active_sessions > 0 {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(counters.snapshot().active_sessions, 0);

    stop.store(true, Ordering::Relaxed);
    handle.join().expect("join server");
}

#[test]
fn tun_mode_requires_psk_and_ip_pool_plus_ipv4_classifier() {
    // --mode tun without --psk MUST fail safely
    let insecure_tun = RelayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        mode: RelayMode::Tun {
            tun_name: "jiter0".to_string(),
        },
        psk: None,
        ..RelayConfig::default()
    };
    assert!(RelayServer::bind(insecure_tun).is_err());

    // Ephemeral IP pool tests
    let mut pool = TunIpPool::new([10, 77, 0]);
    let ip1 = pool.allocate(1001).unwrap();
    let ip2 = pool.allocate(1002).unwrap();
    assert_eq!(ip1, [10, 77, 0, 2]);
    assert_eq!(ip2, [10, 77, 0, 3]);
    assert_eq!(pool.lookup_session_by_ip(ip1), Some(1001));
    assert_eq!(pool.active_leases(), 2);
    pool.release_session(1001);
    assert_eq!(pool.lookup_session_by_ip(ip1), None);
    assert_eq!(pool.active_leases(), 1);

    // IPv4 parser & 3-tier classifier check
    let mut game_udp = vec![0u8; 88];
    game_udp[0] = 0x45;
    game_udp[3] = 88;
    game_udp[9] = 17; // UDP
    game_udp[12..16].copy_from_slice(&[10, 77, 0, 2]);
    game_udp[16..20].copy_from_slice(&[1, 1, 1, 1]);
    game_udp[22..24].copy_from_slice(&30001u16.to_be_bytes());
    let s1 = parse_ipv4_summary(&game_udp).expect("parse game udp");
    assert_eq!(s1.traffic_tier, TrafficTier::Game);
    assert_eq!(s1.src_ip, [10, 77, 0, 2]);

    let mut stream_quic = vec![0u8; 1200];
    stream_quic[0] = 0x45;
    stream_quic[2..4].copy_from_slice(&1200u16.to_be_bytes());
    stream_quic[9] = 17; // UDP large -> STREAMING
    stream_quic[12..16].copy_from_slice(&[142, 250, 190, 78]);
    stream_quic[16..20].copy_from_slice(&[10, 77, 0, 2]);
    stream_quic[20..22].copy_from_slice(&443u16.to_be_bytes());
    let s2 = parse_ipv4_summary(&stream_quic).expect("parse stream quic");
    assert_eq!(s2.traffic_tier, TrafficTier::Streaming);
    assert_eq!(s2.dst_ip, [10, 77, 0, 2]);
}
