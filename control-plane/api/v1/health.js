"use strict";

module.exports = async function handler(_req, res) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.status(200).end(
    JSON.stringify({
      ok: true,
      service: "jiter-control-plane",
      version: "0.7.0",
      serverTimeMs: Date.now(),
    }),
  );
};
