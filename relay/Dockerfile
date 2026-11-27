FROM rust:1.83-slim-bookworm AS builder

WORKDIR /src
COPY engine-rust ./engine-rust
COPY relay ./relay

WORKDIR /src/relay
RUN cargo build --release

FROM debian:bookworm-slim

RUN useradd --system --no-create-home jiter
COPY --from=builder /src/relay/target/release/jiter-relay /usr/local/bin/jiter-relay

USER jiter
EXPOSE 51820/udp

ENTRYPOINT ["/usr/local/bin/jiter-relay"]
CMD ["--bind", "0.0.0.0:51820", "--region", "JKT-1", "--mode", "echo", "--max-link-mbps", "50"]
