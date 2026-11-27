#!/usr/bin/env bash
# JITER Stage 4 Linux VPS Gateway Setup (Jakarta / Singapore Edge)
# Configures:
#   1. Persistent TUN interface `jiter0` (10.77.0.1/24, MTU 1280)
#   2. IPv4 forwarding + Linux BBR + FQ qdisc + socket buffer tuning
#   3. iptables NAT MASQUERADE + TCP MSS clamping for real game + streaming traffic
#   4. Random 256-bit JITER_PSK if not provided
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo $0)" >&2
  exit 1
fi

TUN_IFACE="${TUN_IFACE:-jiter0}"
TUN_SUBNET="${TUN_SUBNET:-10.77.0.0/24}"
TUN_ADDR="${TUN_ADDR:-10.77.0.1/24}"
RELAY_PORT="${RELAY_PORT:-51820}"
WAN_IFACE="${WAN_IFACE:-$(ip route show default | awk '/default/ {print $5; exit}')}"

if [ -z "${WAN_IFACE}" ]; then
  echo "Could not auto-detect default WAN interface. Set WAN_IFACE=eth0 and re-run." >&2
  exit 1
fi

echo "==> [1/4] Configuring kernel forwarding, BBR, and FQ qdisc..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr || true
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

echo "==> [2/4] Creating Linux TUN device '${TUN_IFACE}' (${TUN_ADDR}, MTU 1280)..."
ip link show "${TUN_IFACE}" >/dev/null 2>&1 || ip tuntap add dev "${TUN_IFACE}" mode tun
ip addr replace "${TUN_ADDR}" dev "${TUN_IFACE}"
ip link set dev "${TUN_IFACE}" mtu 1280 up

echo "==> [3/4] Configuring iptables NAT MASQUERADE on WAN '${WAN_IFACE}'..."
iptables -t nat -C POSTROUTING -s "${TUN_SUBNET}" -o "${WAN_IFACE}" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "${TUN_SUBNET}" -o "${WAN_IFACE}" -j MASQUERADE
iptables -C FORWARD -i "${TUN_IFACE}" -o "${WAN_IFACE}" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "${TUN_IFACE}" -o "${WAN_IFACE}" -j ACCEPT
iptables -C FORWARD -i "${WAN_IFACE}" -o "${TUN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "${WAN_IFACE}" -o "${TUN_IFACE}" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "==> [4/4] Preparing JITER_PSK..."
if [ -z "${JITER_PSK:-}" ]; then
  JITER_PSK="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
fi

cat <<EOF

====================================================================
JITER Stage 4 Edge Gateway Ready!
  TUN Interface : ${TUN_IFACE} (${TUN_ADDR})
  WAN Interface : ${WAN_IFACE}
  UDP Port      : ${RELAY_PORT}
  JITER_PSK     : ${JITER_PSK}

Start the relay now:
  export JITER_PSK="${JITER_PSK}"
  jiter-relay --bind 0.0.0.0:${RELAY_PORT} --region JKT-1 --mode tun --tun-name ${TUN_IFACE} --max-link-mbps 100

In the JITER Android App -> Configure Backend / Relay:
  - JITER Relay Host / IP : <THIS_VPS_PUBLIC_IP>
  - Relay UDP Port        : ${RELAY_PORT}
  - Relay PSK (AEAD)      : ${JITER_PSK}
  - Tunnel Scope          : Full Internet Tunnel (0.0.0.0/0 + DNS/IPv6 Shield)
====================================================================
EOF
