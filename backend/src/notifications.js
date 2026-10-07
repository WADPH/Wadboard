import fetch from "node-fetch";
import { audit, error as logError, formatTimestamp, getRequestSource, warn as logWarn } from "./logger.js";

const TELEGRAM_TIMEOUT_MS = 5000;

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Host-local time plus its UTC offset, e.g. "2026-10-07 14:32:05 (UTC+03:00)".
function formatHostTime(date = new Date()) {
  const offsetMin = -date.getTimezoneOffset();
  const sign = offsetMin >= 0 ? "+" : "-";
  const abs = Math.abs(offsetMin);
  const hh = String(Math.floor(abs / 60)).padStart(2, "0");
  const mm = String(abs % 60).padStart(2, "0");
  return `${formatTimestamp(date)} (UTC${sign}${hh}:${mm})`;
}

function formatDuration(ms) {
  const total = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h) return `${h}h ${m}m ${s}s`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function classifyIp(ip) {
  const v = String(ip || "").toLowerCase();
  if (!v || v === "unknown") return "";
  if (v === "::1" || v.startsWith("127.")) return "Local";
  if (/^10\./.test(v) || /^192\.168\./.test(v) || /^172\.(1[6-9]|2\d|3[01])\./.test(v)) return "LAN";
  if (/^169\.254\./.test(v) || /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(v)) return "LAN";
  if (/^f[cd]/.test(v) || /^fe[89ab]/.test(v)) return "LAN";
  return "Public";
}

export function createNotificationsModule({ dbApi, authApi }) {
  const db = dbApi.getDB();
  const saveDB = dbApi.saveDB;
  const getTelegramConfig = dbApi.getTelegramConfig;
  const getCameraAlertsConfig = dbApi.getCameraAlertsConfig;
  const normalizeCameraMonitoring = dbApi.normalizeCameraMonitoring;

  // Streams currently open through Wadboard, per camera id.
  const activeViewers = new Map();

  // -----------------------
  // Telegram transport
  // -----------------------
  // `force` skips the global "Telegram Notifications" switch (used by the test
  // button), but credentials are always required.
  async function sendTelegram(text, { silent = false, force = false } = {}) {
    const cfg = getTelegramConfig();
    if (!force && !cfg.enabled) return { ok: false, error: "telegram_disabled" };
    if (!cfg.botToken || !cfg.chatId) {
      logWarn("Telegram notification skipped: bot token/chat ID not configured");
      return { ok: false, error: "telegram_not_configured" };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TELEGRAM_TIMEOUT_MS);
    try {
      const res = await fetch(`https://api.telegram.org/bot${cfg.botToken}/sendMessage`, {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: cfg.chatId,
          text,
          parse_mode: "HTML",
          disable_notification: !!silent,
          disable_web_page_preview: true
        })
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        const description = body && body.description ? body.description : res.statusText;
        logError("Telegram send failed", { status: res.status, description });
        return { ok: false, error: "telegram_http_" + res.status, detail: description };
      }
      return { ok: true };
    } catch (err) {
      logError("Telegram send error", err);
      return { ok: false, error: "telegram_request_failed", detail: err && err.message ? err.message : String(err) };
    } finally {
      clearTimeout(timer);
    }
  }

  // -----------------------
  // Camera view tracking
  // -----------------------
  function describeViewer(req) {
    const source = getRequestSource(req);
    const ua = String(req?.headers?.["user-agent"] || "");
    const lang = String(req?.headers?.["accept-language"] || "").split(",")[0].trim();
    return {
      ip: source.ip,
      ipKind: classifyIp(source.ip),
      session: source.session || "",
      browser: authApi.parseBrowserFromUA(ua),
      os: authApi.parseOsFromUA(ua),
      lang,
      source
    };
  }

  function viewerLines(viewer) {
    const lines = [];
    lines.push(`🌐 IP: <code>${escapeHtml(viewer.ip)}</code>${viewer.ipKind ? ` (${viewer.ipKind})` : ""}`);
    lines.push(`💻 Client: ${escapeHtml(viewer.browser)} on ${escapeHtml(viewer.os)}${viewer.lang ? ` · ${escapeHtml(viewer.lang)}` : ""}`);
    if (viewer.session) lines.push(`🔑 Session: <code>${escapeHtml(viewer.session)}</code>`);
    return lines;
  }

  function shouldNotify(cam, event) {
    if (!getTelegramConfig().enabled || !getCameraAlertsConfig().enabled) return null;
    const rules = normalizeCameraMonitoring(cam.monitoring);
    if (event === "access" && rules.onAccess) return { silent: rules.onAccessSilent };
    if (event === "leave" && rules.onLeave) return { silent: rules.onLeaveSilent };
    return null;
  }

  function notifyInBackground(text, opts) {
    sendTelegram(text, opts).catch(err => logError("Camera notification error", err));
  }

  // Called by the stream route. Returns hooks the stream proxy fires once the
  // upstream outcome is known and when the viewer disconnects.
  function trackCameraView(cam, req) {
    const viewer = describeViewer(req);
    const camName = cam.name || cam.id;
    let openedAt = null;

    return {
      onResult({ ok }) {
        if (ok) {
          openedAt = Date.now();
          activeViewers.set(cam.id, (activeViewers.get(cam.id) || 0) + 1);
        }
        audit(
          "camera.view",
          `${ok ? "Camera viewed" : "Camera view failed (unreachable)"}: ${camName}`,
          viewer.source,
          { id: cam.id }
        );

        const rule = shouldNotify(cam, "access");
        if (!rule) return;
        const lines = [
          `📹 <b>Camera "${escapeHtml(camName)}" has been accessed</b>`,
          `🕒 Time: ${escapeHtml(formatHostTime())}`,
          ...viewerLines(viewer)
        ];
        if (ok) {
          lines.push(`👥 Active Wadboard viewers: ${activeViewers.get(cam.id) || 1}`);
        } else {
          lines.push("⚠️ Camera was unreachable, no video was served");
        }
        notifyInBackground(lines.join("\n"), { silent: rule.silent });
      },

      onEnd() {
        if (openedAt === null) return;
        const duration = Date.now() - openedAt;
        openedAt = null;
        const left = Math.max(0, (activeViewers.get(cam.id) || 1) - 1);
        if (left) activeViewers.set(cam.id, left);
        else activeViewers.delete(cam.id);

        audit("camera.view.end", `Camera view ended: ${camName}`, viewer.source, {
          id: cam.id,
          durationSec: Math.round(duration / 1000)
        });

        const rule = shouldNotify(cam, "leave");
        if (!rule) return;
        const lines = [
          `⏹ <b>Camera "${escapeHtml(camName)}" viewing ended</b>`,
          `🕒 Time: ${escapeHtml(formatHostTime())}`,
          `⏱ Duration: ${formatDuration(duration)}`,
          ...viewerLines(viewer),
          `👥 Active Wadboard viewers: ${left}`
        ];
        notifyInBackground(lines.join("\n"), { silent: rule.silent });
      }
    };
  }

  // -----------------------
  // Routes
  // -----------------------
  function registerRoutes(app) {
    const { requireAdmin } = authApi;

    app.get("/api/telegram", requireAdmin, (req, res) => {
      const cfg = getTelegramConfig();
      res.json({
        enabled: !!cfg.enabled,
        botToken: cfg.botToken || "",
        chatId: cfg.chatId || ""
      });
    });

    app.put("/api/telegram", requireAdmin, (req, res) => {
      const cfg = getTelegramConfig();
      const { enabled, botToken, chatId } = req.body || {};
      if (typeof enabled === "boolean") cfg.enabled = enabled;
      if (typeof botToken === "string") cfg.botToken = botToken.trim();
      if (typeof chatId === "string") cfg.chatId = chatId.trim();
      saveDB();
      audit("telegram.update", `Telegram notifications ${cfg.enabled ? "enabled" : "disabled"}`, getRequestSource(req));
      res.json({ ok: true, enabled: cfg.enabled });
    });

    app.post("/api/telegram/test", requireAdmin, async (req, res) => {
      const text = [
        "✅ <b>Wadboard test notification</b>",
        `🕒 Time: ${escapeHtml(formatHostTime())}`
      ].join("\n");
      const result = await sendTelegram(text, { force: true });
      res.json(result);
    });

    app.get("/api/camera-alerts", requireAdmin, (req, res) => {
      res.json({
        enabled: !!getCameraAlertsConfig().enabled,
        telegramEnabled: !!getTelegramConfig().enabled,
        cameras: db.cameras.map(cam => ({
          id: cam.id,
          name: cam.name,
          monitoring: normalizeCameraMonitoring(cam.monitoring)
        }))
      });
    });

    // `cameras` is optional and partial: only the listed cameras are updated,
    // so cameras created meanwhile in another tab keep their own rules.
    app.put("/api/camera-alerts", requireAdmin, (req, res) => {
      const cfg = getCameraAlertsConfig();
      const { enabled, cameras } = req.body || {};
      if (typeof enabled === "boolean") cfg.enabled = enabled;

      if (Array.isArray(cameras)) {
        const byId = new Map(db.cameras.map(c => [c.id, c]));
        for (const item of cameras) {
          const cam = item && byId.get(item.id);
          if (cam) cam.monitoring = normalizeCameraMonitoring(item.monitoring);
        }
      }

      saveDB();
      audit("camera-alerts.update", `Camera monitoring ${cfg.enabled ? "enabled" : "disabled"}`, getRequestSource(req));
      res.json({ ok: true, enabled: cfg.enabled });
    });
  }

  return {
    sendTelegram,
    trackCameraView,
    registerRoutes
  };
}
