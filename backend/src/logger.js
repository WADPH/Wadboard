import fs from "fs";
import path from "path";
import util from "util";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const LOG_FILE = path.join(__dirname, "..", "wadboard_backend.log");
const LOG_LEVELS = new Set(["INFO", "WARN", "ERROR", "AUDIT"]);

function pad(value) {
  return String(value).padStart(2, "0");
}

function formatTimestamp(date = new Date()) {
  return [
    date.getFullYear(),
    "-",
    pad(date.getMonth() + 1),
    "-",
    pad(date.getDate()),
    " ",
    pad(date.getHours()),
    ":",
    pad(date.getMinutes()),
    ":",
    pad(date.getSeconds())
  ].join("");
}

function formatMeta(meta) {
  if (!meta) return "";
  if (typeof meta === "string") return meta ? ` | ${meta}` : "";
  if (meta instanceof Error) return ` | ${meta.stack || meta.message || String(meta)}`;
  return ` | ${util.inspect(meta, { depth: 5, breakLength: 140, compact: true })}`;
}

function writeLine(line, level) {
  try {
    fs.appendFileSync(LOG_FILE, line + "\n", "utf8");
  } catch (err) {
    const fallback = `[${formatTimestamp()}] [ERROR] logger append failed${formatMeta(err)}`;
    process.stderr.write(fallback + "\n");
  }

  const stream = level === "ERROR" ? process.stderr : process.stdout;
  stream.write(line + "\n");
}

function log(level, message, meta) {
  const normalizedLevel = LOG_LEVELS.has(level) ? level : "INFO";
  const line = `[${formatTimestamp()}] [${normalizedLevel}] ${String(message || "")}${formatMeta(meta)}`;
  writeLine(line, normalizedLevel);
}

function info(message, meta) {
  log("INFO", message, meta);
}

function warn(message, meta) {
  log("WARN", message, meta);
}

function error(message, meta) {
  log("ERROR", message, meta);
}

function audit(action, description, source = null, extra = null) {
  const parts = [`action=${action}`];
  if (description) parts.push(description);
  const meta = {};
  if (source) meta.source = source;
  if (extra) meta.extra = extra;
  log("AUDIT", parts.join(" | "), Object.keys(meta).length ? meta : undefined);
}

function truncate(value, max = 120) {
  const s = String(value || "").replace(/\s+/g, " ").trim();
  if (!s) return "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function getRequestSource(req, extras = {}) {
  const xfwd = req?.headers?.["x-forwarded-for"];
  const ip = typeof xfwd === "string" && xfwd.trim()
    ? xfwd.split(",")[0].trim()
    : String(req?.ip || req?.socket?.remoteAddress || "unknown").replace(/^::ffff:/, "");
  const adminToken = req?.cookies?.adminToken || extras.adminToken || "";
  const viewToken = req?.cookies?.viewToken || extras.viewToken || "";
  const session = adminToken
    ? `admin:${adminToken.slice(0, 8)}`
    : viewToken
      ? `view:${viewToken.slice(0, 8)}`
      : "";

  return {
    ip,
    session: session || undefined,
    userAgent: truncate(req?.headers?.["user-agent"] || extras.userAgent || "", 100)
  };
}

function readRecentLogs(limit = 200) {
  const safeLimit = Math.max(1, Math.min(1000, Number(limit) || 200));
  if (!fs.existsSync(LOG_FILE)) return [];
  const content = fs.readFileSync(LOG_FILE, "utf8");
  const lines = content.split(/\r?\n/).filter(Boolean);
  return lines.slice(-safeLimit);
}

export {
  LOG_FILE,
  formatTimestamp,
  getRequestSource,
  readRecentLogs,
  log,
  info,
  warn,
  error,
  audit
};
