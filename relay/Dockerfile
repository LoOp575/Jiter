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

# Default runs safe diagnostic echo mode.
# For Stage 4 real Linux /dev/net/tun NAT gateway inside Docker, pass:
#   docker run --device /dev/net/tun --cap-add NET_ADMIN --network host \
#     -e JITER_PSK="your-strong-psk" jiter-relay \
#     --bind 0.0.0.0:51820 --region JKT-1 --mode tun --tun-name jiter0
ENTRYPOINT ["/usr/local/bin/jiter-relay"]
CMD ["--bind", "0.0.0.0:51820", "--region", "JKT-1", "--mode", "echo", "--max-link-mbps", "50"]
