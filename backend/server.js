// WADPH Dashboard API with session auth
//
// Data model on disk (wadph-data.json):
// db = {
//   services: [
//     { id, name, openUrl, checkUrl, method, notes,
//       lastStatus, lastChecked }
//       // method = "http" | "ping"
//   ],
//   links: [
//     { id, title, url, icon, notes }
//   ],
//   wol: [
//     {
//       id, name, type, notes,
//       // type = "mikrotik" | "basic" | "wadesp"
//
//       // mikrotik
//       host, user, pass, scriptId,
//
//       // basic
//       mac, broadcast, port, secureon,
//
//       lastRun, lastResult,
//       sshActions: [
//         { id, label, host, user, pass, command, lastRun, lastResult }
//       ]
//     }
//   ],
//   hostActions: [
//     { id, label, command, notes, lastRun, lastResult }
//   ],
//   config: {
//     batteryAlerts: {
//       enabled: boolean,
//       levels: [number, ...],
//       telegramBotToken: string,
//       telegramChatId: string,
//       lastNotifiedLevel: number|null
//     }
//   }
// }

import express from "express";
import cookieParser from "cookie-parser";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import fetch from "node-fetch";
import https from "https";
import { exec } from "child_process";
import crypto from "crypto";

// -----------------------
// Paths / files
// -----------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const DATA_FILE = path.join(__dirname, "wadph-data.json");

// -----------------------
// Session store (in-memory)
// -----------------------
const sessions = {}; // { token: { createdAt: number } }
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

function createSession() {
  const token = crypto.randomBytes(32).toString("hex");
  sessions[token] = { createdAt: Date.now() };
  return token;
}

function getSession(req) {
  const token = req.cookies.adminToken;
  if (!token) return null;
  const sess = sessions[token];
  if (!sess) return null;

  if (Date.now() - sess.createdAt > SESSION_TTL_MS) {
    delete sessions[token];
    return null;
  }
  return { token, createdAt: sess.createdAt };
}

function requireAdmin(req, res, next) {
  const s = getSession(req);
  if (!s) {
    return res.status(401).json({ error: "unauthorized" });
  }
  req.sessionToken = s.token;
  next();
}

// -----------------------
// In-memory DB
// -----------------------
function defaultBatteryAlertsConfig() {
  return {
    enabled: false,
    levels: [30, 15, 5],
    telegramBotToken: "",
    telegramChatId: "",
    lastNotifiedLevel: null
  };
}

function sanitizeBrandText(value) {
  const s = String(value == null ? "" : value);
  return s
    .replace(/[\r\n\t]+/g, " ")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, 40);
}

let db = {
  services: [],
  links: [],
  wol: [],
  hostActions: [],
  config: {
    batteryAlerts: defaultBatteryAlertsConfig(),
    brandText: ""
  },
  admin: {
    passwordHash: null, // <-- ВАЖНО
    initialized: false
  }
};




function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function checkPassword(password) {
  if (!db.admin.initialized || !db.admin.passwordHash) return false;
  return hashPassword(password) === db.admin.passwordHash;
}


function makeId(prefix) {
  return prefix + "-" + Date.now() + "-" + Math.random().toString(16).slice(2);
}

function ensureConfigStructure() {
  if (!db.config || typeof db.config !== "object") {
    db.config = {};
  }
  if (!db.config.batteryAlerts || typeof db.config.batteryAlerts !== "object") {
    db.config.batteryAlerts = defaultBatteryAlertsConfig();
  } else {
    const cfg = db.config.batteryAlerts;
    if (cfg.enabled === undefined) cfg.enabled = false;
    if (!Array.isArray(cfg.levels) || !cfg.levels.length) cfg.levels = [30, 15, 5];
    if (typeof cfg.telegramBotToken !== "string") cfg.telegramBotToken = "";
    if (typeof cfg.telegramChatId !== "string") cfg.telegramChatId = "";
    if (!("lastNotifiedLevel" in cfg)) cfg.lastNotifiedLevel = null;
  }

  if (typeof db.config.brandText !== "string") {
    db.config.brandText = "";
  }

if (!db.admin || typeof db.admin !== "object") {
  db.admin = { passwordHash: null, initialized: false };
}
if (db.admin.initialized === undefined) db.admin.initialized = false;
if (db.admin.passwordHash === undefined) db.admin.passwordHash = null;

}

function getBatteryAlertsConfig() {
  ensureConfigStructure();
  return db.config.batteryAlerts;
}

function getBrandTextConfig() {
  ensureConfigStructure();
  const custom = sanitizeBrandText(db.config.brandText || "");
  return { custom, text: custom || "WELCOME" };
}

function loadDB() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    db = JSON.parse(raw);

    db.services = Array.isArray(db.services) ? db.services : [];
    db.services.forEach(svc => {
      if (svc.notes === undefined)       svc.notes = "";
      if (svc.lastStatus === undefined)  svc.lastStatus = "unknown";
      if (svc.lastChecked === undefined) svc.lastChecked = null;
      if (svc.method === undefined)      svc.method = "http";
    });

    db.links = Array.isArray(db.links) ? db.links : [];
    db.links.forEach(lnk => {
      if (lnk.notes === undefined) lnk.notes = "";
      if (lnk.icon === undefined)  lnk.icon = "🔗";
    });


db.wol.forEach(task => {
  if (!task.type) task.type = "mikrotik";

  if (task.notes === undefined)      task.notes = "";
  if (task.lastRun === undefined)    task.lastRun = null;
  if (task.lastResult === undefined) task.lastResult = "never";

  if (task.type === "wadesp") {
    if (task.espHost === undefined) task.espHost = "";
    if (task.espToken === undefined) task.espToken = "";
  }


  if (!Array.isArray(task.sshActions)) {
    task.sshActions = [];
  }
  task.sshActions.forEach(a => {
    if (!a.id) a.id = makeId("ssh");
    if (a.pass === undefined) a.pass = "";
    if (a.lastRun === undefined) a.lastRun = null;
    if (a.lastResult === undefined) a.lastResult = "never";
  });
});


    db.hostActions = Array.isArray(db.hostActions) ? db.hostActions : [];
    db.hostActions.forEach(a => {
      if (!a.id) a.id = makeId("host");
      if (a.notes === undefined) a.notes = "";
      if (a.lastRun === undefined) a.lastRun = null;
      if (a.lastResult === undefined) a.lastResult = "never";
    });

    ensureConfigStructure();
  } catch (err) {
    console.error("Failed to load DB file. Using empty DB.");
    db = {
      services: [],
      links: [],
      wol: [],
      hostActions: [],
      config: {
        batteryAlerts: defaultBatteryAlertsConfig()
      }
    };
  }
}

function saveDB() {
  ensureConfigStructure();
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), "utf8");
}

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
    saveDB();
  } catch (err) {
    console.error("healthCheckAll error:", err);
  }
}

// -----------------------
// WOL execution (MikroTik, Basic, PowerSW)
// -----------------------

function executeBasicWOL(task) {
  return new Promise(resolve => {
    const mac = (task.mac || "").trim();
    if (!mac) {
      task.lastRun = new Date().toISOString();
      task.lastResult = "invalid_mac";
      saveDB();
      return resolve({ ok: false, result: "invalid_mac", detail: "Missing MAC address" });
    }

    const args = [];
    if (task.broadcast) args.push("-i", task.broadcast);
    if (task.port)      args.push("-p", String(task.port));
    if (task.secureon)  args.push("--passwd", task.secureon);

    args.push(mac);

    const cmd = `wol ${args.join(" ")}`;

    exec(cmd, { timeout: 3000 }, (error, stdout, stderr) => {
      let okFlag, result;
      let detail;
      if (error) {
        okFlag = false;
        result = "error";
        detail = error.message || stderr || "WOL command failed";
      } else {
        okFlag = true;
        result = "ok";
      }

      task.lastRun = new Date().toISOString();
      task.lastResult = result;
      saveDB();
      resolve({ ok: okFlag, result, detail });
    });
  });
}


async function executeWadEspPower(task) {
  const host = (task.espHost || "").trim();
  if (!host) {
    task.lastRun = new Date().toISOString();
    task.lastResult = "invalid_esp_host";
    saveDB();
    return { ok: false, result: "invalid_esp_host", detail: "Missing ESP host" };
  }

  const url = `http://${host}/power/on`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);

  try {
    const res = await fetch(url, {
      method: "POST",
      signal: controller.signal
    });

    if (!res.ok) {
      task.lastRun = new Date().toISOString();
      task.lastResult = "http_" + res.status;
      saveDB();
      return { ok: false, result: "http_" + res.status, detail: res.statusText || "ESP HTTP error" };
    }

    task.lastRun = new Date().toISOString();
    task.lastResult = "ok";
    saveDB();
    return { ok: true, result: "ok" };
  } catch (e) {
    task.lastRun = new Date().toISOString();
    task.lastResult = "error";
    saveDB();
    return { ok: false, result: "error", detail: e && e.message ? e.message : "ESP request failed" };
  } finally {
    clearTimeout(timer);
  }
}


async function executeWOLTask(task) {
  if (task.type === "basic") {
    return executeBasicWOL(task);
  }

  if (task.type === "wadesp") {
    return executeWadEspPower(task);
  }

  // default: mikrotik
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);

  let result = "error";
  let okFlag = false;
  let detail;

  try {
    const creds = Buffer.from(`${task.user}:${task.pass}`).toString("base64");
    const payload = { ".id": `*${task.scriptId}` };

    const res = await fetch(`http://${task.host}/rest/system/script/run`, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Authorization": `Basic ${creds}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (res.status === 200) {
      okFlag = true;
      result = "ok";
    } else {
      result = "http_" + res.status;
      detail = res.statusText || "MikroTik HTTP error";
    }
  } catch (e) {
    result = "error";
    detail = e && e.message ? e.message : "MikroTik request failed";
  } finally {
    clearTimeout(timer);
  }

  task.lastRun = new Date().toISOString();
  task.lastResult = result;
  saveDB();

  return { ok: okFlag, result, detail };
}




// -----------------------
// SSH execution (generic)
// -----------------------
function escapeShellSingleQuotes(str) {
  return String(str).replace(/'/g, `'\\''`);
}

function executeSSHAction(task, action) {
  return new Promise(resolve => {
    const host = (action.host || task.host || "").trim();
    const user = (action.user || "").trim();
    const pass = (action.pass || "").trim();
    const command = (action.command || "").trim();

    if (!host || !user || !command) {
      const result = "invalid_config";
      action.lastRun = new Date().toISOString();
      action.lastResult = result;
      saveDB();
      return resolve({ ok: false, result, detail: "Missing SSH host/user/command" });
    }

    const safeCmd = escapeShellSingleQuotes(command);
    // If password is provided, use sshpass for interactive login; otherwise fall back to key-based auth
    const sshCmd = pass
      ? `sshpass -p '${escapeShellSingleQuotes(pass)}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 ${user}@${host} '${safeCmd}'`
      : `ssh -o BatchMode=yes -o ConnectTimeout=5 ${user}@${host} '${safeCmd}'`;

    exec(sshCmd, { timeout: 10000 }, (error, stdout, stderr) => {
      let result;
      let okFlag;
      let detail;
      if (error) {
        okFlag = false;
        result = "error";
        detail = error.message || stderr || "SSH command failed";
      } else {
        okFlag = true;
        result = "ok";
      }
      action.lastRun = new Date().toISOString();
      action.lastResult = result;
      saveDB();
      resolve({ ok: okFlag, result, detail });
    });
  });
}

// -----------------------
// Local host actions execution (Termux)
// -----------------------
const INFO_SCRIPT = "/data/data/com.termux/files/home/scripts/info.sh";
const SHELL_BIN   = "/data/data/com.termux/files/usr/bin/bash";

function executeHostAction(action) {
  return new Promise(resolve => {
    const cmd = (action.command || "").trim();
    if (!cmd) {
      const result = "invalid_command";
      action.lastRun = new Date().toISOString();
      action.lastResult = result;
      saveDB();
      return resolve({ ok: false, result, detail: "Missing command" });
    }

    exec(cmd, { timeout: 15000, shell: SHELL_BIN }, (error, stdout, stderr) => {
      let result;
      let okFlag;
      let detail;
      if (error) {
        okFlag = false;
        result = "error";
        detail = error.message || stderr || "Command failed";
      } else {
        okFlag = true;
        result = "ok";
      }
      action.lastRun = new Date().toISOString();
      action.lastResult = result;
      saveDB();
      resolve({ ok: okFlag, result, detail });
    });
  });
}

// -----------------------
// State sanitization
// -----------------------
function sanitizeForClient(isAdmin) {
  if (isAdmin) {
    return db;
  }

  return {
    services: db.services.map(s => ({ ...s })),
    links: db.links.map(l => ({ ...l })),
    wol: db.wol.map(w => ({
  id: w.id,
  name: w.name,
  type: w.type,
  notes: w.notes || "",
  lastRun: w.lastRun || null,
  lastResult: w.lastResult || "never",
  sshActions: Array.isArray(w.sshActions)
    ? w.sshActions.map(a => ({
        id: a.id,
        label: a.label,
        lastRun: a.lastRun || null,
        lastResult: a.lastResult || "never"
      }))
    : []
})),
    hostActions: Array.isArray(db.hostActions)
      ? db.hostActions.map(a => ({
          id: a.id,
          label: a.label,
          notes: a.notes || "",
          lastRun: a.lastRun || null,
          lastResult: a.lastResult || "never"
        }))
      : []
  };
}

// -----------------------
// Express app
// -----------------------
const app = express();

app.use(express.json());
app.use(cookieParser());

// -----------------------
// Frontend (SPA) serving
// -----------------------
const FRONTEND_DIR = path.join(__dirname, "..", "frontend");
const FRONTEND_INDEX = path.join(FRONTEND_DIR, "index.html");
if (fs.existsSync(FRONTEND_INDEX)) {
  app.use(express.static(FRONTEND_DIR));

  // SPA-style route for /health (and direct loads on /)
  app.get(["/", "/health"], (req, res) => {
    res.sendFile(FRONTEND_INDEX);
  });
}

// -----------------------
// Termux info.sh integration (host info header)
// -----------------------
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

// -----------------------
// Battery alerts (Telegram)
// -----------------------
async function sendBatteryAlert(level, percentage) {
  const cfg = getBatteryAlertsConfig();
  if (!cfg.telegramBotToken || !cfg.telegramChatId) {
    console.warn("Battery alert enabled but Telegram token/chat not configured");
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
      console.error("Battery alert send failed:", res.status, res.statusText);
      return false;
    }
    return true;
  } catch (err) {
    console.error("Battery alert send error:", err && err.message ? err.message : err);
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
        console.error("Battery alert error:", err);
      });
  }
}

function pollHostInfoOnce() {
  return new Promise((resolve) => {
    exec(`${INFO_SCRIPT}`, { shell: SHELL_BIN, timeout: 4000 }, (err, stdout) => {
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
        console.error("checkBatteryAlerts error:", e);
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

// public read-only endpoint
app.get("/api/hostinfo", (req, res) => {
  res.json(hostInfo);
});

// -----------------------
// Host health metrics (public read-only)
// -----------------------
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

app.get("/api/health", async (req, res) => {
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
    console.error("/api/health error:", e && e.message ? e.message : e);
    res.status(500).json({ ok: false, error: "health_failed" });
  }
});

// -----------------------
// Battery alerts config endpoints (admin)
// -----------------------
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

// -----------------------
// Brand text endpoints
// -----------------------
app.get("/api/brand-text", (req, res) => {
  const cfg = getBrandTextConfig();
  res.json({ text: cfg.text, custom: cfg.custom });
});

app.put("/api/brand-text", requireAdmin, (req, res) => {
  ensureConfigStructure();
  const { text } = req.body || {};
  const cleaned = sanitizeBrandText(text);
  db.config.brandText = cleaned || "";
  saveDB();
  const cfg = getBrandTextConfig();
  res.json({ ok: true, text: cfg.text, custom: cfg.custom });
});

// -----------------------
// Auth endpoints
// -----------------------
app.post("/api/login", (req, res) => {
  const { password } = req.body || {};
// first-time setup
if (!db.admin.initialized) {
  if (!password || password.length < 6) {
    return res.status(400).json({ error: "password_too_short" });
  }

  db.admin.passwordHash = hashPassword(password);
  db.admin.initialized = true;
  saveDB();
} else {
  if (!checkPassword(password)) {
    return res.status(401).json({ error: "bad_password" });
  }
}



  const token = createSession();

  res.cookie("adminToken", token, {
    httpOnly: true,
    sameSite: "strict",
    maxAge: SESSION_TTL_MS,
    secure: false
  });

  return res.json({ ok: true });
});



app.put("/api/admin/password", requireAdmin, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "password_too_short" });
  }

  if (!checkPassword(oldPassword)) {
    return res.status(401).json({ error: "bad_password" });
  }

  db.admin.passwordHash = hashPassword(newPassword);
  saveDB();

  res.json({ ok: true });
});


app.get("/api/admin/status", (req, res) => {
  res.json({
    initialized: !!db.admin.initialized
  });
});



app.post("/api/logout", (req, res) => {
  const token = req.cookies.adminToken;
  if (token) {
    delete sessions[token];
  }

  res.clearCookie("adminToken", {
    sameSite: "strict",
    secure: false
  });

  return res.json({ ok: true });
});

// -----------------------
// Read-only state
// -----------------------
app.get("/api/state", (req, res) => {
  const isAdmin = !!getSession(req);
  res.json(sanitizeForClient(isAdmin));
});

// -----------------------
// Manual refresh endpoint
// -----------------------
app.post("/api/refresh", async (req, res) => {
  try {
    await healthCheckAll();
    await pollHostInfoOnce();
    res.json({ ok: true });
  } catch (e) {
    console.error("refresh error:", e);
    res.status(500).json({ ok: false, error: "refresh_failed" });
  }
});

// -----------------------
// SERVICES CRUD
// -----------------------
app.post("/api/service", requireAdmin, (req, res) => {
  const { name, openUrl, checkUrl, method, notes } = req.body || {};
  if (!name || !openUrl || !checkUrl) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const safeMethod = (method === "ping" || method === "http") ? method : "http";

  const newSvc = {
    id: makeId("svc"),
    name,
    openUrl,
    checkUrl,
    method: safeMethod,
    notes: notes || "",
    lastStatus: "unknown",
    lastChecked: null
  };

  db.services.push(newSvc);
  saveDB();
  res.json(newSvc);
});

app.put("/api/service/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  const svc = db.services.find(s => s.id === id);
  if (!svc) return res.status(404).json({ error: "Service not found" });

  const { name, openUrl, checkUrl, method, notes } = req.body || {};
  if (name      !== undefined) svc.name      = name;
  if (openUrl   !== undefined) svc.openUrl   = openUrl;
  if (checkUrl  !== undefined) svc.checkUrl  = checkUrl;
  if (notes     !== undefined) svc.notes     = notes;
  if (method    !== undefined) {
    svc.method = (method === "ping" || method === "http") ? method : "http";
  }

  saveDB();
  res.json(svc);
});

app.delete("/api/service/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  db.services = db.services.filter(s => s.id !== id);
  saveDB();
  res.json({ ok: true });
});

app.put("/api/reorder/services", requireAdmin, (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order)) {
    return res.status(400).json({ error: "order must be array" });
  }

  const map = new Map(db.services.map(s => [s.id, s]));
  const newList = [];
  for (const sid of order) {
    if (map.has(sid)) {
      newList.push(map.get(sid));
      map.delete(sid);
    }
  }
  for (const [, svc] of map) newList.push(svc);

  db.services = newList;
  saveDB();
  res.json({ ok: true });
});

// -----------------------
// LINKS CRUD
// -----------------------
app.post("/api/link", requireAdmin, (req, res) => {
  const { title, url, icon, notes } = req.body || {};
  if (!title || !url) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const newLink = {
    id: makeId("link"),
    title,
    url,
    icon: icon || "🔗",
    notes: notes || ""
  };

  db.links.push(newLink);
  saveDB();
  res.json(newLink);
});

app.put("/api/link/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  const lnk = db.links.find(l => l.id === id);
  if (!lnk) return res.status(404).json({ error: "Link not found" });

  const { title, url, icon, notes } = req.body || {};
  if (title !== undefined) lnk.title = title;
  if (url   !== undefined) lnk.url   = url;
  if (icon  !== undefined) lnk.icon  = icon;
  if (notes !== undefined) lnk.notes = notes;

  saveDB();
  res.json(lnk);
});

app.delete("/api/link/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  db.links = db.links.filter(l => l.id !== id);
  saveDB();
  res.json({ ok: true });
});

app.put("/api/reorder/links", requireAdmin, (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order)) {
    return res.status(400).json({ error: "order must be array" });
  }

  const map = new Map(db.links.map(l => [l.id, l]));
  const newList = [];
  for (const lid of order) {
    if (map.has(lid)) {
      newList.push(map.get(lid));
      map.delete(lid);
    }
  }
  for (const [, lnk] of map) newList.push(lnk);

  db.links = newList;
  saveDB();
  res.json({ ok: true });
});

// -----------------------
// WOL CRUD / RUN + SSH
// -----------------------

app.post("/api/wol", requireAdmin, (req, res) => {
  const { name, type, notes, sshActions } = req.body || {};
  if (!name || !type) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // -----------------------
  // Normalize SSH actions (UNIVERSAL)
  // -----------------------
  let normalizedSshActions = [];
  if (Array.isArray(sshActions)) {
    normalizedSshActions = sshActions
      .map(a => ({
        id: makeId("ssh"),
        label: (a.label || "").trim(),
        host: (a.host || "").trim(),
        user: (a.user || "").trim(),
        pass: (a.pass || "").trim(),
        command: (a.command || "").trim(),
        lastRun: null,
        lastResult: "never"
      }))
      .filter(a => a.label && a.user && a.command);
  }

  // -----------------------
  // Base task
  // -----------------------
  const task = {
    id: makeId("wol"),
    name,
    type,
    notes: notes || "",
    lastRun: null,
    lastResult: "never",
    sshActions: normalizedSshActions
  };

  // -----------------------
  // MikroTik
  // -----------------------
  if (type === "mikrotik") {
    const { host, user, pass, scriptId } = req.body || {};
    if (!host || !user || !pass || !scriptId) {
      return res.status(400).json({ error: "Missing MikroTik fields" });
    }

    task.host = host;
    task.user = user;
    task.pass = pass;
    task.scriptId = scriptId;
  }

  // -----------------------
  // Basic WOL
  // -----------------------
  if (type === "basic") {
    const { mac, broadcast, port, secureon } = req.body || {};
    if (!mac) {
      return res.status(400).json({ error: "Missing MAC address" });
    }

    task.mac = mac;
    task.broadcast = broadcast || "";
    task.port = port || "";
    task.secureon = secureon || "";
  }

  // -----------------------
  // WadESP-PowerSW
  // -----------------------
if (type === "wadesp") {
  const { espHost, espToken } = req.body || {};
  if (!espHost) {
    return res.status(400).json({ error: "Missing ESP host or token" });
  }

  task.espHost = espHost;
  task.espToken = espToken;
}

  // -----------------------
  // Save
  // -----------------------
  db.wol.push(task);
  saveDB();
  res.json(task);
});




app.put("/api/wol/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  const task = db.wol.find(a => a.id === id);
  if (req.body.type !== undefined) task.type = req.body.type;
  if (!task) return res.status(404).json({ error: "WOL task not found" });

  const {
  name,
  host,
  user,
  pass,
  scriptId,
  notes,
  sshActions,
  espHost,
  mac,
  broadcast,
  port,
  secureon
} = req.body || {};

if (task.type === "basic") {
  if (mac !== undefined) task.mac = mac;
  if (broadcast !== undefined) task.broadcast = broadcast;
  if (port !== undefined) task.port = port;
  if (secureon !== undefined) task.secureon = secureon;
}

if (task.type === "wadesp") {
  if (espHost !== undefined) task.espHost = espHost;
}



  if (name     !== undefined) task.name     = name;
  if (host     !== undefined) task.host     = host;
  if (user     !== undefined) task.user     = user;
  if (pass     !== undefined) task.pass     = pass;
  if (scriptId !== undefined) task.scriptId = scriptId;
  if (notes    !== undefined) task.notes    = notes;

  if (sshActions !== undefined) {
    if (Array.isArray(sshActions)) {
      task.sshActions = sshActions
        .map(a => ({
          id: makeId("ssh"),
          label: (a.label || "").trim(),
          host: (a.host || task.host).trim(),
          user: (a.user || "").trim(),
          pass: (a.pass || "").trim(),
          command: (a.command || "").trim(),
          lastRun: null,
          lastResult: "never"
        }))
        .filter(a => a.label && a.user && a.command);
    } else {
      task.sshActions = [];
    }
  }

  saveDB();
  res.json(task);
});

app.delete("/api/wol/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  db.wol = db.wol.filter(a => a.id !== id);
  saveDB();
  res.json({ ok: true });
});

app.put("/api/reorder/wol", requireAdmin, (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order)) {
    return res.status(400).json({ error: "order must be array" });
  }

  const map = new Map(db.wol.map(a => [a.id, a]));
  const newList = [];
  for (const wid of order) {
    if (map.has(wid)) {
      newList.push(map.get(wid));
      map.delete(wid);
    }
  }
  for (const [, task] of map) newList.push(task);

  db.wol = newList;
  saveDB();
  res.json({ ok: true });
});

app.post("/api/wol/:id/run", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const task = db.wol.find(a => a.id === id);
  if (!task) return res.status(404).json({ error: "WOL task not found" });

  const result = await executeWOLTask(task);
  res.json(result);
});

app.post("/api/wol/:id/ssh/:actionId/run", requireAdmin, async (req, res) => {
  const { id, actionId } = req.params;
  const task = db.wol.find(a => a.id === id);
  if (!task) return res.status(404).json({ error: "WOL task not found" });

  const actions = Array.isArray(task.sshActions) ? task.sshActions : [];
  const action = actions.find(a => a.id === actionId);
  if (!action) return res.status(404).json({ error: "SSH action not found" });

  const result = await executeSSHAction(task, action);
  res.json(result);
});

// -----------------------
// Host actions CRUD / RUN
// -----------------------
app.post("/api/host-action", requireAdmin, (req, res) => {
  const { label, command, notes } = req.body || {};
  if (!label || !command) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const newAction = {
    id: makeId("host"),
    label: label.trim(),
    command: command.trim(),
    notes: (notes || "").trim(),
    lastRun: null,
    lastResult: "never"
  };

  db.hostActions.push(newAction);
  saveDB();
  res.json(newAction);
});

app.put("/api/host-action/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  const action = db.hostActions.find(a => a.id === id);
  if (!action) return res.status(404).json({ error: "Host action not found" });

  const { label, command, notes } = req.body || {};
  if (label   !== undefined) action.label   = String(label).trim();
  if (command !== undefined) action.command = String(command).trim();
  if (notes   !== undefined) action.notes   = String(notes).trim();

  saveDB();
  res.json(action);
});

app.delete("/api/host-action/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  db.hostActions = db.hostActions.filter(a => a.id !== id);
  saveDB();
  res.json({ ok: true });
});

app.post("/api/host-action/:id/run", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const action = db.hostActions.find(a => a.id === id);
  if (!action) return res.status(404).json({ error: "Host action not found" });

  const result = await executeHostAction(action);
  res.json(result);
});

// -----------------------
// Start server
// -----------------------
const PORT = 4000;

loadDB();

healthCheckAll().catch(err => {
  console.error("initial healthCheckAll error:", err);
});

app.listen(PORT, () => {
  console.log("WADPH Dashboard API running on port " + PORT);
});

setInterval(() => {
  healthCheckAll().catch(err => {
    console.error("interval healthCheckAll error:", err);
  });
}, 10000);
