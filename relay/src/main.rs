use std::env;
use std::net::SocketAddr;
use std::process;

use jiter_relay::server::{RelayConfig, RelayMode, RelayServer};

fn print_usage() {
    println!(
        "JITER Edge Relay Server (Stage 3)\n\
         \n\
         USAGE:\n\
           jiter-relay [OPTIONS]\n\
         \n\
         OPTIONS:\n\
           --bind <IP:PORT>            UDP listen address (default: 0.0.0.0:51820)\n\
           --region <TAG>              Region tag up to 8 chars (default: JKT-1, e.g. SG-1)\n\
           --mode <echo|forward>       Operating mode (default: echo)\n\
           --upstream <IP:PORT>        Upstream UDP target when --mode forward\n\
           --max-link-mbps <FLOAT>     Default downlink pacing budget in Mbps (default: 50.0)\n\
           --session-timeout-secs <N>  Idle RAM session TTL in seconds (default: 60)\n\
           --help                      Show this help message"
    );
}

fn parse_args() -> Result<RelayConfig, String> {
    let mut cfg = RelayConfig::default();
    let mut mode_str = "echo".to_string();
    let mut upstream_str: Option<String> = None;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            "--bind" => {
                i += 1;
                let val = args.get(i).ok_or("--bind requires <IP:PORT>")?;
                cfg.bind_addr = val
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("invalid --bind '{val}': {e}"))?;
            }
            "--region" => {
                i += 1;
                let val = args.get(i).ok_or("--region requires <TAG>")?;
                cfg.region_tag = val.chars().take(8).collect();
            }
            "--mode" => {
                i += 1;
                mode_str = args.get(i).ok_or("--mode requires echo|forward")?.clone();
            }
            "--upstream" => {
                i += 1;
                upstream_str = Some(args.get(i).ok_or("--upstream requires <IP:PORT>")?.clone());
            }
            "--max-link-mbps" => {
                i += 1;
                let val = args.get(i).ok_or("--max-link-mbps requires a number")?;
                cfg.default_link_mbps = val
                    .parse::<f64>()
                    .map_err(|e| format!("invalid --max-link-mbps '{val}': {e}"))?;
            }
            "--session-timeout-secs" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or("--session-timeout-secs requires seconds")?;
                cfg.session_timeout_secs = val
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --session-timeout-secs '{val}': {e}"))?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }

    cfg.mode = match mode_str.as_str() {
        "echo" => RelayMode::Echo,
        "forward" => {
            let up = upstream_str
                .ok_or("--upstream <IP:PORT> is required when --mode forward")?
                .parse::<SocketAddr>()
                .map_err(|e| format!("invalid --upstream: {e}"))?;
            RelayMode::Forward(up)
        }
        other => return Err(format!("invalid --mode '{other}' (expected echo or forward)")),
    };

    Ok(cfg)
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}\n");
            print_usage();
            process::exit(2);
        }
    };

    println!(
        "[JITER-RELAY] Starting edge node region={} bind={} mode={:?} link_budget={}Mbps (RAM-only zero-log)",
        cfg.region_tag, cfg.bind_addr, cfg.mode, cfg.default_link_mbps
    );

    let mut server = match RelayServer::bind(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[JITER-RELAY] Failed to bind UDP socket: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = server.run() {
        eprintln!("[JITER-RELAY] Runtime error: {e}");
        process::exit(1);
    }
}
