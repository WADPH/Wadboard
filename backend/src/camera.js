import fetch from "node-fetch";
import { audit, error as logError } from "./logger.js";

const CONTROL_TIMEOUT_MS = 5000;
const STATUS_TIMEOUT_MS = 4000;

export function createCameraModule({ dbApi }) {
  const saveDB = dbApi.saveDB;

  // -----------------------
  // tobi01001/IP_Cam transport helpers
  // -----------------------
  function buildCameraUrl(camera, pathAndQuery) {
    const host = String(camera.host || "").trim();
    const port = String(camera.port || "").trim();
    return `http://${host}:${port}${pathAndQuery}`;
  }

  function getAuthHeaders(camera) {
    const username = String(camera.username || "");
    const password = String(camera.password || "");
    if (!username && !password) return {};
    const creds = Buffer.from(`${username}:${password}`).toString("base64");
    return { Authorization: `Basic ${creds}` };
  }

  async function fetchJson(camera, pathAndQuery, { timeoutMs = STATUS_TIMEOUT_MS } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(buildCameraUrl(camera, pathAndQuery), {
        signal: controller.signal,
        headers: getAuthHeaders(camera)
      });
      if (!res.ok) {
        return { ok: false, error: "http_" + res.status };
      }
      const data = await res.json().catch(() => null);
      return { ok: true, data };
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : "request_failed" };
    } finally {
      clearTimeout(timer);
    }
  }

  async function callControl(camera, pathAndQuery) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CONTROL_TIMEOUT_MS);
    try {
      const res = await fetch(buildCameraUrl(camera, pathAndQuery), {
        signal: controller.signal,
        headers: getAuthHeaders(camera)
      });
      if (!res.ok) {
        return { ok: false, result: "http_" + res.status };
      }
      return { ok: true, result: "ok" };
    } catch (err) {
      return { ok: false, result: "error", detail: err && err.message ? err.message : "request_failed" };
    } finally {
      clearTimeout(timer);
    }
  }

  async function runControlAction(camera, pathAndQuery, { auditAction, auditLabel, context = {} } = {}) {
    const outcome = await callControl(camera, pathAndQuery);
    camera.lastRun = new Date().toISOString();
    camera.lastResult = outcome.result;
    saveDB();
    audit(
      auditAction,
      `${outcome.ok ? "Camera action executed" : "Camera action failed"}: ${auditLabel || camera.name || camera.id}`,
      context.source,
      { result: outcome.result }
    );
    return { ok: outcome.ok, result: outcome.result, detail: outcome.detail };
  }

  // -----------------------
  // Health-cycle probe (lightweight reachability check, mirrors probeService)
  // -----------------------
  async function probeCameraStatus(camera) {
    const host = String(camera.host || "").trim();
    if (!host || !camera.port) {
      camera.lastStatus = "unknown";
      camera.lastChecked = new Date().toISOString();
      return;
    }
    const result = await fetchJson(camera, "/status", { timeoutMs: STATUS_TIMEOUT_MS });
    camera.lastStatus = result.ok ? "UP" : "DOWN";
    camera.lastChecked = new Date().toISOString();
  }

  // -----------------------
  // Read-only proxy endpoints
  // -----------------------
  async function proxySnapshot(camera, res) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), STATUS_TIMEOUT_MS);
    try {
      const upstream = await fetch(buildCameraUrl(camera, "/snapshot"), {
        signal: controller.signal,
        headers: getAuthHeaders(camera)
      });
      if (!upstream.ok) {
        return res.status(502).json({ error: "camera_unreachable" });
      }
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.setHeader("Content-Type", upstream.headers.get("content-type") || "image/jpeg");
      res.send(buf);
    } catch (err) {
      logError("Camera snapshot proxy error", err);
      res.status(502).json({ error: "camera_unreachable" });
    } finally {
      clearTimeout(timer);
    }
  }

  // MJPEG is a long-lived connection: the upstream fetch is aborted as soon as
  // either side disconnects, otherwise a viewer closing the tab would leave the
  // request (and the camera's connection slot) open indefinitely.
  async function proxyStream(camera, req, res) {
    const controller = new AbortController();
    const onClose = () => controller.abort();
    req.on("close", onClose);

    try {
      const upstream = await fetch(buildCameraUrl(camera, "/stream"), {
        signal: controller.signal,
        headers: getAuthHeaders(camera)
      });

      if (!upstream.ok || !upstream.body) {
        req.removeListener("close", onClose);
        return res.status(502).json({ error: "camera_unreachable" });
      }

      res.status(200);
      const contentType = upstream.headers.get("content-type");
      if (contentType) res.setHeader("Content-Type", contentType);

      upstream.body.on("error", () => {
        try { res.end(); } catch { /* ignore */ }
      });
      res.on("close", () => controller.abort());
      upstream.body.pipe(res);
    } catch (err) {
      req.removeListener("close", onClose);
      if (!res.headersSent) {
        res.status(502).json({ error: "camera_unreachable", detail: err && err.message ? err.message : String(err) });
      } else {
        try { res.end(); } catch { /* ignore */ }
      }
    }
  }

  async function getStatus(camera) {
    return fetchJson(camera, "/status");
  }

  async function getConnections(camera) {
    return fetchJson(camera, "/connections");
  }

  // -----------------------
  // Control actions (admin-gated at the route level)
  // -----------------------
  function runSwitch(camera, context) {
    return runControlAction(camera, "/switch", { auditAction: "camera.switch", context });
  }

  function runFlashlight(camera, action, context) {
    const path = action === "on" ? "/flashOn" : action === "off" ? "/flashOff" : "/toggleFlashlight";
    return runControlAction(camera, path, { auditAction: "camera.flashlight", context });
  }

  function runRotation(camera, value, context) {
    const allowed = ["0", "90", "180", "270"];
    const v = String(value);
    if (!allowed.includes(v)) {
      return Promise.resolve({ ok: false, result: "invalid_value" });
    }
    camera.rotation = Number(v);
    return runControlAction(camera, `/setRotation?value=${v}`, { auditAction: "camera.rotation", context });
  }

  function runRestart(camera, context) {
    return runControlAction(camera, "/restart", { auditAction: "camera.restart", context });
  }

  return {
    probeCameraStatus,
    proxySnapshot,
    proxyStream,
    getStatus,
    getConnections,
    runSwitch,
    runFlashlight,
    runRotation,
    runRestart
  };
}
