import fs from "fs";
import os from "os";
import https from "https";
import fetch from "node-fetch";
import { exec } from "child_process";
import { error as logError, warn as logWarn } from "./logger.js";

export function createHealthModule({ dbApi }) {
  const db = dbApi.getDB();
  const saveDB = dbApi.saveDB;
  const getBatteryAlertsConfig = dbApi.getBatteryAlertsConfig;
  const DEFAULT_INFO_SCRIPT = "/data/data/com.termux/files/home/scripts/info.sh";
  const TERMUX_SHELL_BIN = "/data/data/com.termux/files/usr/bin/bash";

  // -----------------------
  // Health check helpers
  // -----------------------
  const insecureAgent = new https.Agent({
    rejectUnauthorized: false
  });

  function isHealthyHttpStatus(code) {
    if ((code >= 200 && code < 400) || code === 401 || code === 403) {
      return true;
    }
    return false;
  }

  async function httpAlive(urlToCheck) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);

    async function tryOnce(allowInsecure) {
      const opts = { method: "GET", signal: controller.signal };
      if (allowInsecure && urlToCheck.startsWith("https")) {
        opts.agent = insecureAgent;
      }
      const res = await fetch(urlToCheck, opts);
      return isHealthyHttpStatus(res.status);
    }

    try {
      const ok1 = await tryOnce(false);
      if (ok1) {
        clearTimeout(timer);
        return true;
      }
      try {
        const ok2 = await tryOnce(true);
        clearTimeout(timer);
        return ok2;
      } catch {
        clearTimeout(timer);
        return false;
      }
    } catch {
      try {
        const ok2 = await tryOnce(true);
        clearTimeout(timer);
        return ok2;
      } catch {
        clearTimeout(timer);
        return false;
      }
    }
  }

  function pingHostOnce(host) {
    return new Promise(resolve => {
      exec(`ping -c 1 -w 2 ${host}`, (error) => {
        if (error) resolve(false);
        else resolve(true);
      });
    });
  }

  async function probeService(svc) {
    let status = "DOWN";

    if (svc.method === "ping") {
      try {
        const alive = await pingHostOnce(svc.checkUrl);
        status = alive ? "UP" : "DOWN";
      } catch {
        status = "DOWN";
      }
    } else {
      try {
        const ok = await httpAlive(svc.checkUrl);
        status = ok ? "UP" : "DOWN";
      } catch {
        status = "DOWN";
      }
    }

    svc.lastStatus  = status;
    svc.lastChecked = new Date().toISOString();
  }

  async function healthCheckAll() {
    try {
      for (const svc of db.services) {
        await probeService(svc);
      }
      for (const task of db.wol) {
        await probeWol(task);
      }
      saveDB();
    } catch (err) {
      logError("healthCheckAll error", err);
    }
  }

  async function probeWol(task) {
    const target = (task.statusTarget || "").trim();
    if (!target) {
      task.lastStatus = "unknown";
      task.lastChecked = new Date().toISOString();
      return;
    }

    const method = (task.statusMethod === "ping" || task.statusMethod === "http")
      ? task.statusMethod
      : "http";

    let status = "DOWN";
    if (method === "ping") {
      try {
        const alive = await pingHostOnce(target);
        status = alive ? "UP" : "DOWN";
      } catch {
        status = "DOWN";
      }
    } else {
      try {
        const ok = await httpAlive(target);
        status = ok ? "UP" : "DOWN";
      } catch {
        status = "DOWN";
      }
    }

    task.lastStatus = status;
    task.lastChecked = new Date().toISOString();
  }


  let hostInfo = {
    ip: null,
    rssi: null,
    ssid: null,
    health: null,
    status: null,
    temperature: null,
    percentage: null,
    updatedAt: null,
    ok: false,
    lastError: null
  };

  function parseInfoOutput(text) {
    const out = {};
    const re = /^\s*"([^"]+)"\s*:\s*(.+?)(,|\s*$)/gm;
    let m;
    while ((m = re.exec(text)) !== null) {
      const k = m[1];
      let v = m[2].trim();
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      if (!isNaN(Number(v))) v = Number(v);
      out[k] = v;
    }
    return {
      ip:          out.ip ?? null,
      rssi:        out.rssi ?? null,
      ssid:        out.ssid ?? null,
      health:      out.health ?? null,
      status:      out.status ?? null,
      temperature: out.temperature ?? null,
      percentage:  out.percentage ?? null
    };
  }

  function resolveInfoScriptPath() {
    const candidates = [
      process.env.WADBOARD_INFO_SCRIPT,
      DEFAULT_INFO_SCRIPT
    ].filter(Boolean);
    for (const candidate of candidates) {
      if (candidate && fs.existsSync(candidate)) return candidate;
    }
    return candidates[0] || null;
  }

  function resolveInfoShellPath() {
    const candidates = [
      process.env.SHELL,
      TERMUX_SHELL_BIN,
      "/bin/bash",
      "/bin/sh"
    ].filter(Boolean);
    for (const candidate of candidates) {
      if (candidate && fs.existsSync(candidate)) return candidate;
    }
    return null;
  }

  // -----------------------
  // Battery alerts (Telegram)
  // -----------------------
  async function sendBatteryAlert(level, percentage) {
    const cfg = getBatteryAlertsConfig();
    if (!cfg.telegramBotToken || !cfg.telegramChatId) {
      logWarn("Battery alert enabled but Telegram token/chat not configured");
      return false;
    }

    const text = `🪫Wadboard host battery low: ${percentage}% (threshold ${level}%)`;
    const url = `https://api.telegram.org/bot${cfg.telegramBotToken}/sendMessage`;
    const payload = {
      chat_id: cfg.telegramChatId,
      text
    };

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(url, {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      clearTimeout(timer);

      if (!res.ok) {
        logError("Battery alert send failed", { status: res.status, statusText: res.statusText });
        return false;
      }
      return true;
    } catch (err) {
      logError("Battery alert send error", err);
      return false;
    }
  }

  function checkBatteryAlerts() {
    const cfg = getBatteryAlertsConfig();
    if (!cfg.enabled) return;

    const pct = Number(hostInfo.percentage);
    if (!Number.isFinite(pct)) return;

    const levelsRaw = Array.isArray(cfg.levels) && cfg.levels.length ? cfg.levels : [30, 15, 5];
    const levels = levelsRaw
      .map(v => parseInt(v, 10))
      .filter(n => Number.isFinite(n) && n > 0 && n <= 100)
      .sort((a, b) => b - a);
    if (!levels.length) return;

    const highest = levels[0];

    // If battery went above highest threshold, reset lastNotifiedLevel
    if (pct > highest && cfg.lastNotifiedLevel !== null) {
      cfg.lastNotifiedLevel = null;
      saveDB();
      return;
    }

    // Notify on each threshold crossing (30 -> 15 -> 5), even if the percentage
    // skips over a value between polls.
    let targetLevel = null;
    for (const lvl of levels) {
      if (pct <= lvl && (cfg.lastNotifiedLevel === null || lvl < cfg.lastNotifiedLevel)) {
        targetLevel = lvl;
        break;
      }
    }

    if (targetLevel !== null) {
      sendBatteryAlert(targetLevel, pct)
        .then(() => {
          cfg.lastNotifiedLevel = targetLevel;
          saveDB();
        })
        .catch(err => {
          logError("Battery alert error", err);
        });
    }
  }

  function pollHostInfoOnce() {
    return new Promise((resolve) => {
      const infoScriptPath = resolveInfoScriptPath();
      const infoShellPath = resolveInfoShellPath();

      if (!infoScriptPath || !fs.existsSync(infoScriptPath)) {
        hostInfo.ok = false;
        hostInfo.lastError = "info_script_missing";
        hostInfo.updatedAt = new Date().toISOString();
        return resolve(false);
      }

      if (!infoShellPath) {
        hostInfo.ok = false;
        hostInfo.lastError = "shell_not_found";
        hostInfo.updatedAt = new Date().toISOString();
        return resolve(false);
      }

      exec(`${infoScriptPath}`, { shell: infoShellPath, timeout: 4000 }, (err, stdout) => {
        if (err) {
          hostInfo.ok = false;
          hostInfo.lastError = String(err.message || err);
          hostInfo.updatedAt = new Date().toISOString();
          return resolve(false);
        }
        const parsed = parseInfoOutput(stdout || "");
        hostInfo = {
          ...hostInfo,
          ...parsed,
          ok: true,
          lastError: null,
          updatedAt: new Date().toISOString()
        };

        // After host info is updated, check battery alerts
        try {
          checkBatteryAlerts();
        } catch (e) {
          logError("checkBatteryAlerts error", e);
        }

        resolve(true);
      });
    });
  }

  // initial poll + interval
  pollHostInfoOnce().catch(() => {});
  setInterval(() => {
    pollHostInfoOnce().catch(() => {});
  }, 60_000);

  // read-only endpoint

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async function getCpuUsagePercent() {
    // Prefer /proc/stat on Linux/Android (Termux) because Node's os.cpus()
    // can return non-updating times on some Android builds.
    try {
      if (fs.existsSync("/proc/stat")) {
        const readProcStatText = async () => {
          try {
            return fs.readFileSync("/proc/stat", "utf8");
          } catch (e) {
            const code = e && e.code ? String(e.code) : "";
            if (code !== "EACCES" && code !== "EPERM") throw e;

            // Some Android/Termux devices restrict /proc/stat; try root via su.
            const suRes = await execCmd('su -c "cat /proc/stat"', { timeoutMs: 1200 });
            if (suRes.ok && suRes.stdout) return suRes.stdout;
            throw e;
          }
        };

        const parseTotalsFromText = (txt) => {
          const line = txt.split("\n").find(l => /^cpu\s/.test(l));
          if (!line) return null;

          const parts = line.trim().split(/\s+/).slice(1).map(v => parseInt(v, 10));
          if (parts.length < 4 || parts.some(v => !Number.isFinite(v))) return null;

          const [
            user, nice, system, idle,
            iowait = 0, irq = 0, softirq = 0, steal = 0
          ] = parts;

          const idleAll = idle + iowait;
          const nonIdle = user + nice + system + irq + softirq + steal;
          const total = idleAll + nonIdle;
          return { idle: idleAll, total };
        };

        const aTxt = await readProcStatText();
        const a = parseTotalsFromText(aTxt);
        await sleep(250);
        const bTxt = await readProcStatText();
        const b = parseTotalsFromText(bTxt);
        if (!a || !b) return null;

        const totalDelta = b.total - a.total;
        const idleDelta = b.idle - a.idle;
        if (!(totalDelta > 0)) return null;

        const usage = 100 * (1 - (idleDelta / totalDelta));
        const rounded = Math.round(usage * 10) / 10;
        return Math.max(0, Math.min(100, rounded));
      }
    } catch (e) {
      const code = e && e.code ? String(e.code) : "";
      if (code === "EACCES" || code === "EPERM") throw e;
      // ignore; fall back below
    }

    try {
      const start = os.cpus();
      if (!Array.isArray(start) || !start.length) return null;
      await sleep(200);
      const end = os.cpus();
      if (!Array.isArray(end) || !end.length) return null;

      let idle = 0;
      let total = 0;

      const len = Math.min(start.length, end.length);
      for (let i = 0; i < len; i++) {
        const s = start[i].times;
        const e = end[i].times;
        const idleDelta = (e.idle - s.idle);
        const totalDelta =
          (e.user - s.user) +
          (e.nice - s.nice) +
          (e.sys - s.sys) +
          (e.irq - s.irq) +
          (e.idle - s.idle);

        idle += idleDelta;
        total += totalDelta;
      }

      if (!(total > 0)) return null;
      const usage = 100 * (1 - (idle / total));
      const rounded = Math.round(usage * 10) / 10;
      return Math.max(0, Math.min(100, rounded));
    } catch {
      return null;
    }
  }

  async function getCpuUsage() {
    try {
      const pct = await getCpuUsagePercent();
      if (Number.isFinite(pct)) return { usagePercent: pct, hint: null };
      return { usagePercent: null, hint: "CPU usage unavailable" };
    } catch (e) {
      const code = e && e.code ? String(e.code) : "";
      if (code === "EACCES" || code === "EPERM") {
        return {
          usagePercent: null,
          hint: 'CPU usage requires access to "/proc/stat". On some Android/Termux devices this needs root. Start Wadboard as root (e.g. `tsu` / `su`) or grant root.'
        };
      }
      return { usagePercent: null, hint: "CPU usage unavailable" };
    }
  }

  function getCpuCoreCount() {
    try {
      const n = os.cpus().length;
      if (Number.isFinite(n) && n > 0) return n;
    } catch {
      // ignore
    }

    try {
      if (fs.existsSync("/proc/cpuinfo")) {
        const txt = fs.readFileSync("/proc/cpuinfo", "utf8");
        const count = txt
          .split("\n")
          .filter(l => /^\s*processor\s*:/.test(l))
          .length;
        if (count > 0) return count;
      }
    } catch {
      // ignore
    }

    try {
      if (fs.existsSync("/proc/stat")) {
        const txt = fs.readFileSync("/proc/stat", "utf8");
        const count = txt
          .split("\n")
          .filter(l => /^cpu\d+\s/.test(l))
          .length;
        if (count > 0) return count;
      }
    } catch {
      // ignore
    }

    return null;
  }

  function getPrimaryIPv4() {
    try {
      const nets = os.networkInterfaces();
      for (const name of Object.keys(nets)) {
        const list = nets[name] || [];
        for (const n of list) {
          if (!n) continue;
          if (n.family === "IPv4" && !n.internal) return n.address;
        }
      }
    } catch {
      // ignore
    }
    return null;
  }

  function execCmd(cmd, { timeoutMs = 2000 } = {}) {
    return new Promise(resolve => {
      exec(cmd, { timeout: timeoutMs }, (err, stdout, stderr) => {
        if (err) {
          const msg = `${stderr || ""} ${err.message || ""}`.toLowerCase();
          const missing =
            msg.includes("not found") ||
            msg.includes("no such file") ||
            msg.includes("is not recognized") ||
            err.code === 127;
          return resolve({
            ok: false,
            missing,
            stdout: stdout || "",
            stderr: stderr || "",
            error: err.message || String(err)
          });
        }
        resolve({ ok: true, stdout: stdout || "", stderr: stderr || "" });
      });
    });
  }

  function isAndroidLike() {
    return !!(
      process.env.ANDROID_ROOT ||
      process.env.ANDROID_DATA ||
      (typeof os.release === "function" && String(os.release()).toLowerCase().includes("android"))
    );
  }

  function pickStoragePath() {
    if (!isAndroidLike()) return "/";

    const candidates = [
      "/storage/emulated/0",
      "/storage/emulated",
      "/data/media/0",
      "/data/media"
    ];

    for (const p of candidates) {
      try {
        if (fs.existsSync(p) && fs.statSync(p).isDirectory()) return p;
      } catch {
        // ignore
      }
    }

    return "/";
  }

  async function getDiskUsage(pathToCheck) {
    const safePath = pathToCheck || "/";
    const r = await execCmd(`df -kP ${safePath}`, { timeoutMs: 2000 });
    if (!r.ok) {
      return {
        available: false,
        path: safePath,
        hint: r.missing ? "Install coreutils (df)" : (r.error || "df failed")
      };
    }

    const lines = String(r.stdout || "").trim().split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) {
      return { available: false, path: safePath, hint: "Unexpected df output" };
    }

    const parts = lines[lines.length - 1].trim().split(/\s+/);
    if (parts.length < 6) {
      return { available: false, path: safePath, hint: "Unexpected df columns" };
    }

    const totalKiB = parseInt(parts[1], 10);
    const usedKiB = parseInt(parts[2], 10);
    const availKiB = parseInt(parts[3], 10);
    const usedPct = parseInt(String(parts[4]).replace("%", ""), 10);
    const mount = parts[5];

    if (![totalKiB, usedKiB, availKiB].every(Number.isFinite)) {
      return { available: false, path: safePath, hint: "Unexpected df numbers" };
    }

    return {
      available: true,
      path: safePath,
      mount,
      totalBytes: totalKiB * 1024,
      usedBytes: usedKiB * 1024,
      freeBytes: availKiB * 1024,
      usedPercent: Number.isFinite(usedPct) ? usedPct : null
    };
  }

  async function getBatteryInfo() {
    // Termux (termux-api package + Termux:API app)
    const termux = await execCmd("termux-battery-status", { timeoutMs: 1500 });
    if (termux.ok) {
      try {
        const j = JSON.parse(termux.stdout);
        return {
          available: true,
          percent: Number.isFinite(Number(j.percentage)) ? Number(j.percentage) : null,
          status: typeof j.status === "string" ? j.status : null
        };
      } catch {
        return { available: false, hint: "termux-battery-status returned invalid JSON" };
      }
    }
    if (termux.missing) {
      // try upower (Linux desktop/server)
      const devs = await execCmd("upower -e", { timeoutMs: 1500 });
      if (!devs.ok) {
        return {
          available: false,
          hint: devs.missing
            ? "Install termux-api (Termux) or upower (Ubuntu/Debian)"
            : (devs.error || "Battery info unavailable")
        };
      }

      const bat = devs.stdout
        .split(/\r?\n/)
        .map(s => s.trim())
        .find(s => s.toLowerCase().includes("battery"));

      if (!bat) return { available: false, hint: "No battery device found" };

      const info = await execCmd(`upower -i ${bat}`, { timeoutMs: 1500 });
      if (!info.ok) {
        return {
          available: false,
          hint: info.missing ? "Install upower" : (info.error || "upower failed")
        };
      }

      const pctLine = info.stdout.split(/\r?\n/).find(l => l.trim().startsWith("percentage:"));
      const stateLine = info.stdout.split(/\r?\n/).find(l => l.trim().startsWith("state:"));
      const pct = pctLine ? parseInt(pctLine.split(":")[1].replace("%", "").trim(), 10) : null;
      const state = stateLine ? stateLine.split(":")[1].trim() : null;
      return { available: true, percent: Number.isFinite(pct) ? pct : null, status: state };
    }

    return {
      available: false,
      hint: termux.error || "Battery info unavailable"
    };
  }


  function registerRoutes(app, { authApi }) {
    const { requireAdmin, requireViewAccess } = authApi;

    app.get("/api/hostinfo", requireViewAccess, (req, res) => {
      res.json(hostInfo);
    });

    app.get("/api/health", requireViewAccess, async (req, res) => {
      try {
        const cpuUsage = await getCpuUsage();
        const totalBytes = os.totalmem();
        const freeBytes = os.freemem();
        const usedBytes = totalBytes - freeBytes;
        const memPct = totalBytes > 0 ? Math.round((usedBytes / totalBytes) * 1000) / 10 : null;

        const storagePath = pickStoragePath();
        const disk = await getDiskUsage(storagePath);
        const battery = await getBatteryInfo();

        res.json({
          ok: true,
          updatedAt: new Date().toISOString(),
          system: {
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            release: os.release(),
            uptimeSec: os.uptime()
          },
          cpu: {
            cores: getCpuCoreCount(),
            usagePercent: cpuUsage.usagePercent,
            hint: cpuUsage.hint,
            loadavg: os.loadavg()
          },
          memory: {
            totalBytes,
            usedBytes,
            freeBytes,
            usedPercent: memPct
          },
          disk,
          storage: disk,
          network: {
            ipv4: getPrimaryIPv4()
          },
          battery
        });
      } catch (e) {
        logError("/api/health error", e);
        res.status(500).json({ ok: false, error: "health_failed" });
      }
    });

    app.get("/api/battery-alerts", requireAdmin, (req, res) => {
      const cfg = getBatteryAlertsConfig();
      res.json({
        enabled: !!cfg.enabled,
        levels: Array.isArray(cfg.levels) ? cfg.levels : [30, 15, 5],
        telegramBotToken: cfg.telegramBotToken || "",
        telegramChatId: cfg.telegramChatId || ""
      });
    });

    app.put("/api/battery-alerts", requireAdmin, (req, res) => {
      const cfg = getBatteryAlertsConfig();
      const { enabled, levels, telegramBotToken, telegramChatId } = req.body || {};

      if (typeof enabled === "boolean") {
        cfg.enabled = enabled;
      }

      if (Array.isArray(levels)) {
        const norm = levels
          .map(v => parseInt(v, 10))
          .filter(n => Number.isFinite(n) && n > 0 && n <= 100);
        if (norm.length) {
          norm.sort((a, b) => b - a);
          cfg.levels = norm;
        }
      }

      if (typeof telegramBotToken === "string") {
        cfg.telegramBotToken = telegramBotToken.trim();
      }
      if (typeof telegramChatId === "string") {
        cfg.telegramChatId = telegramChatId.trim();
      }

      saveDB();

      res.json({
        ok: true,
        config: {
          enabled: cfg.enabled,
          levels: cfg.levels
        }
      });
    });

  }

  function startMonitoring() {
    pollHostInfoOnce().catch(() => {});
    healthCheckAll().catch(err => {
      logError("initial healthCheckAll error", err);
    });
    setInterval(() => {
      healthCheckAll().catch(err => {
        logError("interval healthCheckAll error", err);
      });
    }, 10000);
  }

  return {
    registerRoutes,
    startMonitoring,
    healthCheckAll,
    pollHostInfoOnce
  };
}
