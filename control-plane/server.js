"use strict";

const http = require("http");
const {
  SlidingRateLimiter,
  handleBootstrapRequest,
} = require("./lib/bootstrap-core");

function readJsonBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk.toString("utf8");
      if (raw.length > maxBytes) {
        raw = "";
      }
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        const parsed = JSON.parse(raw);
        resolve(parsed && typeof parsed === "object" ? parsed : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

function createServer(env = process.env) {
  const limiter = new SlidingRateLimiter(env.JITER_RATE_LIMIT_RPM || 60);

  return http.createServer(async (req, res) => {
    const urlPath = (req.url || "/").split("?")[0];
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, max-age=0");

    if (urlPath === "/api/v1/health" && req.method === "GET") {
      res.writeHead(200);
      res.end(
        JSON.stringify({
          ok: true,
          service: "jiter-control-plane",
          version: "0.6.0",
          serverTimeMs: Date.now(),
        }),
      );
      return;
    }

    if (urlPath === "/api/v1/session/bootstrap") {
      const body = req.method === "POST" ? await readJsonBody(req) : {};
      const clientIp = String(
        req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown",
      )
        .split(",")[0]
        .trim();

      const result = await handleBootstrapRequest({
        method: req.method,
        headers: req.headers,
        body,
        clientIp,
        env,
        rateLimiter: limiter,
      });

      res.writeHead(result.status);
      res.end(JSON.stringify(result.json));
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ ok: false, error: "NOT_FOUND" }));
  });
}

if (require.main === module) {
  const host = process.env.HOST || "0.0.0.0";
  const port = Number(process.env.PORT || 8787);
  const server = createServer(process.env);
  server.listen(port, host, () => {
    console.log(`[JITER-CONTROL-PLANE] Listening on http://${host}:${port}`);
  });
}

module.exports = { createServer };
