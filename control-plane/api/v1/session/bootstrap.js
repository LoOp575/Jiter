"use strict";

const {
  SlidingRateLimiter,
  handleBootstrapRequest,
} = require("../../../lib/bootstrap-core");

const globalLimiter = new SlidingRateLimiter(process.env.JITER_RATE_LIMIT_RPM || 60);

module.exports = async function handler(req, res) {
  const forwarded = req.headers["x-forwarded-for"];
  const clientIp = Array.isArray(forwarded)
    ? forwarded[0]
    : String(forwarded || req.socket?.remoteAddress || "unknown").split(",")[0].trim();

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }

  const result = await handleBootstrapRequest({
    method: req.method,
    headers: req.headers,
    body: body && typeof body === "object" ? body : {},
    clientIp,
    env: process.env,
    rateLimiter: globalLimiter,
  });

  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.status(result.status).end(JSON.stringify(result.json));
};
