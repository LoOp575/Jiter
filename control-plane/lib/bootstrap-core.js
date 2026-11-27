"use strict";

const crypto = require("crypto");

const DEFAULT_POLICY = Object.freeze({
  tunnelScope: "FULL_INTERNET_TUNNEL",
  routingMode: "HYBRID_ADAPTIVE",
  failurePolicy: "FAIL_OPEN",
  fecPolicy: "AUTO_ADAPTIVE",
  probeHost: "1.1.1.1",
  probePort: 443,
  ttlSeconds: 300,
});

const VALID_TUNNEL_SCOPES = new Set(["DIAGNOSTIC_SUBNET", "FULL_INTERNET_TUNNEL"]);
const VALID_ROUTING_MODES = new Set(["PRIVACY_ALWAYS_TUNNEL", "HYBRID_ADAPTIVE"]);
const VALID_FAILURE_POLICIES = new Set(["FAIL_OPEN", "FAIL_CLOSED"]);
const VALID_FEC_POLICIES = new Set(["AUTO_ADAPTIVE", "FORCE_OFF", "FORCE_K2_LOW_LAT"]);

class SlidingRateLimiter {
  constructor(maxPerMinute = 60) {
    this.maxPerMinute = Math.max(1, Number(maxPerMinute) || 60);
    this.buckets = new Map();
  }

  allow(ipKey, nowMs = Date.now()) {
    const key = String(ipKey || "unknown");
    const windowStart = nowMs - 60_000;
    let stamps = this.buckets.get(key) || [];
    stamps = stamps.filter((ts) => ts > windowStart);
    if (stamps.length >= this.maxPerMinute) {
      this.buckets.set(key, stamps);
      return false;
    }
    stamps.push(nowMs);
    this.buckets.set(key, stamps);

    // Keep RAM bounded
    if (this.buckets.size > 4096) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey) this.buckets.delete(oldestKey);
    }
    return true;
  }
}

function constantTimeStringEqual(a, b) {
  const bufA = Buffer.from(String(a || ""), "utf8");
  const bufB = Buffer.from(String(b || ""), "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function sanitizePolicy(raw = {}) {
  const tunnelScope = VALID_TUNNEL_SCOPES.has(raw.tunnelScope)
    ? raw.tunnelScope
    : DEFAULT_POLICY.tunnelScope;
  const routingMode = VALID_ROUTING_MODES.has(raw.routingMode)
    ? raw.routingMode
    : DEFAULT_POLICY.routingMode;
  const failurePolicy = VALID_FAILURE_POLICIES.has(raw.failurePolicy)
    ? raw.failurePolicy
    : DEFAULT_POLICY.failurePolicy;
  const fecPolicy = VALID_FEC_POLICIES.has(raw.fecPolicy)
    ? raw.fecPolicy
    : DEFAULT_POLICY.fecPolicy;
  const probeHost =
    typeof raw.probeHost === "string" && raw.probeHost.trim().length > 0
      ? raw.probeHost.trim()
      : DEFAULT_POLICY.probeHost;
  const probePortNum = Number(raw.probePort);
  const probePort =
    Number.isInteger(probePortNum) && probePortNum >= 1 && probePortNum <= 65535
      ? probePortNum
      : DEFAULT_POLICY.probePort;
  const ttlNum = Number(raw.ttlSeconds);
  const ttlSeconds =
    Number.isInteger(ttlNum) && ttlNum >= 30 && ttlNum <= 3600
      ? ttlNum
      : DEFAULT_POLICY.ttlSeconds;

  return {
    tunnelScope,
    routingMode,
    failurePolicy,
    fecPolicy,
    probeHost,
    probePort,
    ttlSeconds,
  };
}

function normalizeNode(raw) {
  if (!raw || typeof raw !== "object") return null;
  if (raw.enabled === false) return null;
  const host = typeof raw.host === "string" ? raw.host.trim() : "";
  const port = Number(raw.port ?? 51820);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }
  const region =
    typeof raw.region === "string" && raw.region.trim().length > 0
      ? raw.region.trim().slice(0, 8)
      : "EDGE";
  const id =
    typeof raw.id === "string" && raw.id.trim().length > 0
      ? raw.id.trim()
      : `${region.toLowerCase()}-${port}`;
  const psk =
    typeof raw.psk === "string"
      ? raw.psk.trim()
      : typeof raw.psk_secret === "string"
        ? raw.psk_secret.trim()
        : "";
  const priority = Number.isFinite(Number(raw.priority)) ? Number(raw.priority) : 10;
  const maxSessions = Math.max(1, Number(raw.maxSessions ?? raw.max_sessions ?? 2000) || 2000);
  const activeLoad = Math.max(0, Number(raw.activeLoad ?? raw.active_load ?? 0) || 0);

  return {
    id,
    region,
    host,
    port,
    psk,
    priority,
    loadRatio: Math.min(1.0, activeLoad / maxSessions),
  };
}

function rankNodes(nodes, preferredRegion = "") {
  const pref = String(preferredRegion || "").trim().toUpperCase();
  return [...nodes]
    .sort((a, b) => {
      const aMatch = pref && a.region.toUpperCase().startsWith(pref) ? 0 : 1;
      const bMatch = pref && b.region.toUpperCase().startsWith(pref) ? 0 : 1;
      if (aMatch !== bMatch) return aMatch - bMatch;
      if (a.loadRatio !== b.loadRatio) return a.loadRatio - b.loadRatio;
      return a.priority - b.priority;
    })
    .map(({ id, region, host, port, psk, priority }) => ({
      id,
      region,
      host,
      port,
      psk,
      priority,
    }));
}

async function fetchFromSupabase(env, fetchImpl = globalThis.fetch) {
  const baseUrl = String(env.SUPABASE_URL || "").replace(/\/+$/, "");
  const serviceKey = String(env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
  if (!baseUrl || !serviceKey || typeof fetchImpl !== "function") {
    return null;
  }

  const headers = {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    Accept: "application/json",
  };

  const [nodesRes, policyRes] = await Promise.all([
    fetchImpl(
      `${baseUrl}/rest/v1/jiter_relay_nodes?enabled=eq.true&select=id,region,host,port,psk_secret,priority,max_sessions,active_load,enabled`,
      { headers },
    ),
    fetchImpl(
      `${baseUrl}/rest/v1/jiter_client_policy?id=eq.default&select=tunnel_scope,routing_mode,failure_policy,fec_policy,probe_host,probe_port,ttl_seconds`,
      { headers },
    ),
  ]);

  if (!nodesRes.ok) {
    throw new Error(`Supabase nodes query failed: HTTP ${nodesRes.status}`);
  }
  const rawNodes = await nodesRes.json();
  let rawPolicy = {};
  if (policyRes.ok) {
    const rows = await policyRes.json();
    if (Array.isArray(rows) && rows.length > 0) {
      const r = rows[0];
      rawPolicy = {
        tunnelScope: r.tunnel_scope,
        routingMode: r.routing_mode,
        failurePolicy: r.failure_policy,
        fecPolicy: r.fec_policy,
        probeHost: r.probe_host,
        probePort: r.probe_port,
        ttlSeconds: r.ttl_seconds,
      };
    }
  }

  return {
    source: "supabase",
    nodes: Array.isArray(rawNodes) ? rawNodes.map(normalizeNode).filter(Boolean) : [],
    policy: sanitizePolicy(rawPolicy),
  };
}

function loadFromEnv(env) {
  let parsedNodes = [];
  if (env.JITER_RELAY_NODES_JSON) {
    try {
      const arr = JSON.parse(env.JITER_RELAY_NODES_JSON);
      if (Array.isArray(arr)) {
        parsedNodes = arr.map(normalizeNode).filter(Boolean);
      }
    } catch {
      parsedNodes = [];
    }
  } else if (env.JITER_RELAY_HOST) {
    const single = normalizeNode({
      id: "default-edge",
      region: env.JITER_RELAY_REGION || "JKT-1",
      host: env.JITER_RELAY_HOST,
      port: Number(env.JITER_RELAY_PORT || 51820),
      psk: env.JITER_RELAY_PSK || env.JITER_PSK || "",
      priority: 1,
    });
    if (single) parsedNodes.push(single);
  }

  const policy = sanitizePolicy({
    tunnelScope: env.JITER_DEFAULT_TUNNEL_SCOPE,
    routingMode: env.JITER_DEFAULT_ROUTING_MODE,
    failurePolicy: env.JITER_DEFAULT_FAILURE_POLICY,
    fecPolicy: env.JITER_DEFAULT_FEC_POLICY,
    probeHost: env.JITER_DEFAULT_PROBE_HOST,
    probePort: env.JITER_DEFAULT_PROBE_PORT ? Number(env.JITER_DEFAULT_PROBE_PORT) : undefined,
    ttlSeconds: env.JITER_BOOTSTRAP_TTL_SECS ? Number(env.JITER_BOOTSTRAP_TTL_SECS) : undefined,
  });

  return {
    source: parsedNodes.length > 0 ? "env" : "empty",
    nodes: parsedNodes,
    policy,
  };
}

/**
 * Core zero-config bootstrap handler shared by Vercel API functions & standalone Node server.
 */
async function handleBootstrapRequest({
  method,
  headers = {},
  body = {},
  clientIp = "unknown",
  env = process.env,
  rateLimiter,
  fetchImpl = globalThis.fetch,
}) {
  if (method !== "POST" && method !== "GET") {
    return { status: 405, json: { ok: false, error: "METHOD_NOT_ALLOWED" } };
  }

  if (rateLimiter && !rateLimiter.allow(clientIp)) {
    return { status: 429, json: { ok: false, error: "RATE_LIMITED" } };
  }

  const requiredAppKey = String(env.JITER_APP_KEY || "").trim();
  if (requiredAppKey) {
    const suppliedKey =
      headers["x-jiter-app-key"] ||
      headers["X-Jiter-App-Key"] ||
      "";
    if (!constantTimeStringEqual(requiredAppKey, suppliedKey)) {
      return { status: 401, json: { ok: false, error: "UNAUTHORIZED_APP_KEY" } };
    }
  }

  const preferredRegion =
    typeof body.preferredRegion === "string" ? body.preferredRegion : "";

  let loaded = null;
  try {
    loaded = await fetchFromSupabase(env, fetchImpl);
  } catch {
    loaded = null;
  }
  if (!loaded) {
    loaded = loadFromEnv(env);
  }

  const ranked = rankNodes(loaded.nodes, preferredRegion).slice(0, 6);

  return {
    status: 200,
    json: {
      ok: true,
      serverTimeMs: Date.now(),
      source: loaded.source,
      ttlSeconds: loaded.policy.ttlSeconds,
      policy: {
        tunnelScope: loaded.policy.tunnelScope,
        routingMode: loaded.policy.routingMode,
        failurePolicy: loaded.policy.failurePolicy,
        fecPolicy: loaded.policy.fecPolicy,
        probeHost: loaded.policy.probeHost,
        probePort: loaded.policy.probePort,
      },
      nodes: ranked,
    },
  };
}

module.exports = {
  DEFAULT_POLICY,
  SlidingRateLimiter,
  sanitizePolicy,
  normalizeNode,
  rankNodes,
  handleBootstrapRequest,
};
