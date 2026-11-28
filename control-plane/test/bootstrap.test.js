"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SlidingRateLimiter,
  handleBootstrapRequest,
} = require("../lib/bootstrap-core");
const { createServer } = require("../server");

test("bootstrap ranks enabled nodes by preferred region, load, and priority", async () => {
  const env = {
    JITER_RELAY_NODES_JSON: JSON.stringify([
      {
        id: "sg-busy",
        region: "SG-1",
        host: "198.51.100.1",
        port: 51820,
        psk: "psk-sg-1",
        priority: 1,
        maxSessions: 100,
        activeLoad: 90,
        enabled: true,
      },
      {
        id: "jkt-disabled",
        region: "JKT-2",
        host: "203.0.113.99",
        port: 51820,
        psk: "psk-off",
        enabled: false,
      },
      {
        id: "jkt-primary",
        region: "JKT-1",
        host: "203.0.113.10",
        port: 51820,
        psk: "psk-jkt-1",
        priority: 2,
        maxSessions: 100,
        activeLoad: 20,
        enabled: true,
      },
    ]),
    JITER_DEFAULT_TUNNEL_SCOPE: "FULL_INTERNET_TUNNEL",
  };

  const res = await handleBootstrapRequest({
    method: "POST",
    body: { preferredRegion: "JKT" },
    env,
  });

  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
  assert.equal(res.json.source, "env");
  assert.equal(res.json.nodes.length, 2);
  assert.equal(res.json.nodes[0].id, "jkt-primary");
  assert.equal(res.json.nodes[0].psk, "psk-jkt-1");
  assert.equal(res.json.nodes[1].id, "sg-busy");
  assert.equal(res.json.policy.tunnelScope, "FULL_INTERNET_TUNNEL");

  const hybridRes = await handleBootstrapRequest({
    method: "POST",
    env: { JITER_DEFAULT_TUNNEL_SCOPE: "HYBRID_AUTO" },
  });
  assert.equal(hybridRes.status, 200);
  assert.equal(hybridRes.json.nodes.length, 0);
  assert.equal(hybridRes.json.policy.tunnelScope, "HYBRID_AUTO");
});

test("bootstrap enforces optional X-Jiter-App-Key and rate limiting", async () => {
  const limiter = new SlidingRateLimiter(2);
  const env = {
    JITER_APP_KEY: "secret-app-token-2026",
    JITER_RELAY_HOST: "203.0.113.10",
    JITER_RELAY_PSK: "node-psk",
  };

  const unauthorized = await handleBootstrapRequest({
    method: "POST",
    headers: { "x-jiter-app-key": "wrong-key" },
    clientIp: "10.0.0.1",
    env,
    rateLimiter: limiter,
  });
  assert.equal(unauthorized.status, 401);

  const ok = await handleBootstrapRequest({
    method: "POST",
    headers: { "x-jiter-app-key": "secret-app-token-2026" },
    clientIp: "10.0.0.1",
    env,
    rateLimiter: limiter,
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.nodes.length, 1);

  const limited = await handleBootstrapRequest({
    method: "POST",
    headers: { "x-jiter-app-key": "secret-app-token-2026" },
    clientIp: "10.0.0.1",
    env,
    rateLimiter: limiter,
  });
  assert.equal(limited.status, 429);
});

test("standalone HTTP server serves health and bootstrap over real TCP", async () => {
  const srv = createServer({
    JITER_RELAY_HOST: "127.0.0.1",
    JITER_RELAY_PORT: "51820",
    JITER_RELAY_REGION: "JKT-1",
    JITER_RELAY_PSK: "live-test-psk",
  });

  await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
  const { port } = srv.address();

  try {
    const healthRes = await fetch(`http://127.0.0.1:${port}/api/v1/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = await healthRes.json();
    assert.equal(healthJson.ok, true);

    const bootRes = await fetch(`http://127.0.0.1:${port}/api/v1/session/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ appVersion: "0.6.0-stage5-onetap", preferredRegion: "JKT" }),
    });
    assert.equal(bootRes.status, 200);
    const bootJson = await bootRes.json();
    assert.equal(bootJson.ok, true);
    assert.equal(bootJson.nodes[0].host, "127.0.0.1");
    assert.equal(bootJson.nodes[0].region, "JKT-1");
    assert.equal(bootJson.nodes[0].psk, "live-test-psk");
  } finally {
    await new Promise((resolve) => srv.close(resolve));
  }
});
