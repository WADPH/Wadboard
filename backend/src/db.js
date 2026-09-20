import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { error as logError } from "./logger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_FILE = path.join(__dirname, "..", "wadph-data.json");
const KEY_FILE = path.join(__dirname, "..", ".secret.key");

// -----------------------
// Password hashing (salted scrypt, with transparent migration
// from the old unsalted SHA-256 scheme)
// -----------------------
const SCRYPT_KEYLEN = 64;
const SCRYPT_SALT_BYTES = 16;

function legacySha256(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

function timingSafeEqualHex(a, b) {
  try {
    const bufA = Buffer.from(String(a), "hex");
    const bufB = Buffer.from(String(b), "hex");
    if (bufA.length === 0 || bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// A random, per-password "salt" is mixed in before hashing and stored next to the
// hash. It guarantees two identical passwords never produce the same hash, which
// defeats precomputed rainbow-table lookups and forces an attacker to brute-force
// each stolen hash individually. scrypt is also deliberately slow/memory-hard
// (unlike a single fast SHA-256 pass), which raises the cost of every guess.
function hashPassword(password) {
  const salt = crypto.randomBytes(SCRYPT_SALT_BYTES);
  const hash = crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN);
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function checkPassword(password) {
  if (!db.admin.initialized || !db.admin.passwordHash) return false;
  const stored = String(db.admin.passwordHash);

  if (stored.startsWith("scrypt$")) {
    const [, saltHex, hashHex] = stored.split("$");
    if (!saltHex || !hashHex) return false;
    let candidateHex;
    try {
      const salt = Buffer.from(saltHex, "hex");
      candidateHex = crypto.scryptSync(String(password), salt, hashHex.length / 2).toString("hex");
    } catch {
      return false;
    }
    return timingSafeEqualHex(candidateHex, hashHex);
  }

  // Legacy unsalted SHA-256 hash from older Wadboard versions. Verify with a
  // constant-time comparison, then transparently upgrade to the salted scheme.
  const matches = timingSafeEqualHex(legacySha256(password), stored);
  if (matches) {
    db.admin.passwordHash = hashPassword(password);
    saveDB();
  }
  return matches;
}

// -----------------------
// Encryption at rest for sensitive credential fields
// -----------------------
function loadOrCreateEncryptionKey() {
  if (process.env.WADBOARD_SECRET_KEY) {
    return crypto.createHash("sha256").update(process.env.WADBOARD_SECRET_KEY).digest();
  }
  try {
    if (fs.existsSync(KEY_FILE)) {
      const hex = fs.readFileSync(KEY_FILE, "utf8").trim();
      if (hex.length === 64) return Buffer.from(hex, "hex");
    }
  } catch (err) {
    logError("Failed to read secret key file, generating a new one.", err);
  }
  const key = crypto.randomBytes(32);
  try {
    fs.writeFileSync(KEY_FILE, key.toString("hex"), { encoding: "utf8", mode: 0o600 });
  } catch (err) {
    logError("Failed to persist secret key file.", err);
  }
  return key;
}

const ENCRYPTION_KEY = loadOrCreateEncryptionKey();

function encryptSecret(plain) {
  const value = String(plain == null ? "" : plain);
  if (!value) return "";
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  const enc = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc$${iv.toString("hex")}$${tag.toString("hex")}$${enc.toString("hex")}`;
}

function decryptSecret(value) {
  const s = String(value == null ? "" : value);
  if (!s.startsWith("enc$")) return s; // plaintext (legacy file or never-encrypted default)
  const parts = s.split("$");
  if (parts.length !== 4) return "";
  const [, ivHex, tagHex, dataHex] = parts;
  try {
    const iv = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");
    const data = Buffer.from(dataHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
  } catch (err) {
    logError("Failed to decrypt stored secret; dropping value.", err);
    return "";
  }
}

// Applies `transform` (encryptSecret or decryptSecret) to every credential-like
// field before the dataset touches disk, so `wadph-data.json` never holds
// SSH/router/bot credentials in plaintext.
function transformSensitiveFields(dbObj, transform) {
  const cloned = JSON.parse(JSON.stringify(dbObj));

  if (Array.isArray(cloned.wol)) {
    cloned.wol.forEach(task => {
      if (task.pass) task.pass = transform(task.pass);
      if (task.secureon) task.secureon = transform(task.secureon);
      if (task.espToken) task.espToken = transform(task.espToken);
      if (Array.isArray(task.sshActions)) {
        task.sshActions.forEach(a => {
          if (a.pass) a.pass = transform(a.pass);
        });
      }
    });
  }

  if (cloned.config && cloned.config.batteryAlerts && cloned.config.batteryAlerts.telegramBotToken) {
    cloned.config.batteryAlerts.telegramBotToken = transform(cloned.config.batteryAlerts.telegramBotToken);
  }

  if (Array.isArray(cloned.cameras)) {
    cloned.cameras.forEach(cam => {
      if (cam.password) cam.password = transform(cam.password);
    });
  }

  return cloned;
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

function buildEmptyDb() {
  return {
    services: [],
    links: [],
    wol: [],
    hostActions: [],
    cameras: [],
    config: {
      batteryAlerts: defaultBatteryAlertsConfig(),
      brandText: "",
      privateMode: false
    },
    admin: {
      passwordHash: null,
      initialized: false
    }
  };
}

// `db` keeps a single stable object identity for the lifetime of the process.
// Other modules capture `dbApi.getDB()` once at startup (`const db = dbApi.getDB()`);
// if this binding were ever reassigned (as it used to be on config import), those
// cached references would silently start reading/writing a stale, detached copy.
// `replaceDbContents` below mutates the existing object instead of replacing it.
let db = buildEmptyDb();

function replaceDbContents(nextData) {
  for (const key of Object.keys(db)) delete db[key];
  Object.assign(db, nextData);
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
if (typeof db.config.privateMode !== "boolean") {
    db.config.privateMode = false;
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

function ensureNormalizedDb(input) {
  const nextDb = (input && typeof input === "object" && !Array.isArray(input))
    ? input
    : buildEmptyDb();

  nextDb.services = Array.isArray(nextDb.services) ? nextDb.services : [];
  nextDb.services.forEach(svc => {
    if (!svc.id) svc.id = makeId("svc");
    if (svc.notes === undefined) svc.notes = "";
    if (svc.lastStatus === undefined) svc.lastStatus = "unknown";
    if (svc.lastChecked === undefined) svc.lastChecked = null;
    if (svc.method === undefined) svc.method = "http";
  });

  nextDb.links = Array.isArray(nextDb.links) ? nextDb.links : [];
  nextDb.links.forEach(lnk => {
    if (!lnk.id) lnk.id = makeId("link");
    if (lnk.notes === undefined) lnk.notes = "";
    if (lnk.icon === undefined) lnk.icon = "🔗";
  });

  nextDb.wol = Array.isArray(nextDb.wol) ? nextDb.wol : [];
  nextDb.wol.forEach(task => {
    if (!task.id) task.id = makeId("wol");
    if (!task.type) task.type = "mikrotik";
    if (task.notes === undefined) task.notes = "";
    if (task.lastRun === undefined) task.lastRun = null;
    if (task.lastResult === undefined) task.lastResult = "never";
    if (task.statusMethod === undefined) task.statusMethod = "http";
    if (task.statusTarget === undefined) task.statusTarget = "";
    if (task.lastStatus === undefined) task.lastStatus = "unknown";
    if (task.lastChecked === undefined) task.lastChecked = null;

    if (task.type === "wadesp") {
      if (task.espHost === undefined) task.espHost = "";
      if (task.espToken === undefined) task.espToken = "";
    }

    if (!Array.isArray(task.sshActions)) {
      task.sshActions = [];
    }
    task.sshActions.forEach(a => {
      if (!a.id) a.id = makeId("ssh");
      if (a.icon === undefined) a.icon = "";
      if (a.pass === undefined) a.pass = "";
      if (a.lastRun === undefined) a.lastRun = null;
      if (a.lastResult === undefined) a.lastResult = "never";
    });
  });

  nextDb.hostActions = Array.isArray(nextDb.hostActions) ? nextDb.hostActions : [];
  nextDb.hostActions.forEach(a => {
    if (!a.id) a.id = makeId("host");
    if (a.icon === undefined) a.icon = "";
    if (a.notes === undefined) a.notes = "";
    if (a.lastRun === undefined) a.lastRun = null;
    if (a.lastResult === undefined) a.lastResult = "never";
  });

  nextDb.cameras = Array.isArray(nextDb.cameras) ? nextDb.cameras : [];
  nextDb.cameras.forEach(cam => {
    if (!cam.id) cam.id = makeId("cam");
    if (!cam.provider) cam.provider = "ip_cam";
    if (cam.notes === undefined) cam.notes = "";
    if (cam.icon === undefined) cam.icon = "";
    if (cam.host === undefined) cam.host = "";
    if (cam.port === undefined) cam.port = "";
    if (cam.username === undefined) cam.username = "";
    if (cam.password === undefined) cam.password = "";
    if (cam.rotation === undefined) cam.rotation = 0;
    if (cam.lastStatus === undefined) cam.lastStatus = "unknown";
    if (cam.lastChecked === undefined) cam.lastChecked = null;
    if (cam.lastRun === undefined) cam.lastRun = null;
    if (cam.lastResult === undefined) cam.lastResult = "never";
  });

  if (nextDb !== db) {
    replaceDbContents(nextDb);
  }
  ensureConfigStructure();
  return db;
}

function replaceDB(nextDb) {
  return ensureNormalizedDb(nextDb);
}

function loadDB() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    const decrypted = transformSensitiveFields(parsed, decryptSecret);
    replaceDB(decrypted);
  } catch (err) {
    logError("Failed to load DB file. Using empty DB.", err);
    replaceDbContents(buildEmptyDb());
    ensureConfigStructure();
  }
}

function saveDB() {
  ensureConfigStructure();
  const encrypted = transformSensitiveFields(db, encryptSecret);
  fs.writeFileSync(DATA_FILE, JSON.stringify(encrypted, null, 2), "utf8");
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
  statusMethod: w.statusMethod || "http",
  statusTarget: w.statusTarget || "",
  lastStatus: w.lastStatus || "unknown",
  lastChecked: w.lastChecked || null,
  lastRun: w.lastRun || null,
  lastResult: w.lastResult || "never",
  sshActions: Array.isArray(w.sshActions)
    ? w.sshActions.map(a => ({
        id: a.id,
        label: a.label,
        icon: a.icon || "",
        lastRun: a.lastRun || null,
        lastResult: a.lastResult || "never"
      }))
    : []
})),
    hostActions: Array.isArray(db.hostActions)
      ? db.hostActions.map(a => ({
          id: a.id,
          label: a.label,
          icon: a.icon || "",
          notes: a.notes || "",
          lastRun: a.lastRun || null,
          lastResult: a.lastResult || "never"
        }))
      : [],
    // host/port/username/password are never sent to non-admin viewers — the
    // frontend only ever talks to cameras through /api/camera/:id/* proxy
    // routes, so it has no legitimate use for the raw connection details.
    cameras: Array.isArray(db.cameras)
      ? db.cameras.map(cam => ({
          id: cam.id,
          name: cam.name,
          icon: cam.icon || "",
          notes: cam.notes || "",
          provider: cam.provider || "ip_cam",
          rotation: cam.rotation || 0,
          lastStatus: cam.lastStatus || "unknown",
          lastChecked: cam.lastChecked || null,
          lastRun: cam.lastRun || null,
          lastResult: cam.lastResult || "never"
        }))
      : []
  };
}
function getDB() {
  return db;
}

export {
  DATA_FILE,
  defaultBatteryAlertsConfig,
  sanitizeBrandText,
  hashPassword,
  checkPassword,
  makeId,
  ensureConfigStructure,
  getBatteryAlertsConfig,
  getBrandTextConfig,
  ensureNormalizedDb,
  loadDB,
  buildEmptyDb,
  replaceDB,
  saveDB,
  sanitizeForClient,
  getDB
};
