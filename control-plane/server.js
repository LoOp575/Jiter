"use strict";

const http = require("http");
const {
  SlidingRateLimiter,
  handleBootstrapRequest,
} = require("./lib/bootstrap-core");

const SERVICE_VERSION = "0.7.0";

function readJsonBody(req, maxBytes = 16 * 1024) {
  // Support platforms (such as Vercel Node serverless runtime) that pre-parse req.body
  if (req.body !== undefined) {
    if (typeof req.body === "string") {
      try {
        const parsed = JSON.parse(req.body);
        return Promise.resolve(parsed && typeof parsed === "object" ? parsed : {});
      } catch {
        return Promise.resolve({});
      }
    }
    if (req.body && typeof req.body === "object") {
      return Promise.resolve(req.body);
    }
  }

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

function createRequestHandler(env = process.env) {
  const limiter = new SlidingRateLimiter(env.JITER_RATE_LIMIT_RPM || 60);

  return async function handleHttp(req, res) {
    const urlPath = (req.url || "/").split("?")[0];
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.setHeader("X-Content-Type-Options", "nosniff");

    if ((urlPath === "/" || urlPath === "/api/v1/health") && req.method === "GET") {
      res.statusCode = 200;
      res.end(
        JSON.stringify({
          ok: true,
          service: "jiter-control-plane",
          version: SERVICE_VERSION,
          serverTimeMs: Date.now(),
        }),
      );
      return;
    }

    if (urlPath === "/api/v1/session/bootstrap") {
      const body = req.method === "POST" ? await readJsonBody(req) : {};
      const forwarded = req.headers["x-forwarded-for"];
      const clientIp = Array.isArray(forwarded)
        ? forwarded[0]
        : String(forwarded || req.socket?.remoteAddress || "unknown")
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

      res.statusCode = result.status;
      res.end(JSON.stringify(result.json));
      return;
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ ok: false, error: "NOT_FOUND" }));
  };
}

function createServer(env = process.env) {
  return http.createServer(createRequestHandler(env));
}

if (require.main === module) {
  const host = process.env.HOST || "0.0.0.0";
  const port = Number(process.env.PORT || 8787);
  const server = createServer(process.env);
  server.listen(port, host, () => {
    console.log(`[JITER-CONTROL-PLANE] Listening on http://${host}:${port}`);
  });
}

const defaultHandler = createRequestHandler(process.env);
defaultHandler.createServer = createServer;
defaultHandler.createRequestHandler = createRequestHandler;

module.exports = defaultHandler;
