import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_FILE = path.join(__dirname, "..", "wadph-data.json");

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
    brandText: "",
    privateMode: false
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
  if (task.statusMethod === undefined) task.statusMethod = "http";
  if (task.statusTarget === undefined) task.statusTarget = "";
  if (task.lastStatus === undefined)   task.lastStatus = "unknown";
  if (task.lastChecked === undefined)  task.lastChecked = null;

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


    db.hostActions = Array.isArray(db.hostActions) ? db.hostActions : [];
    db.hostActions.forEach(a => {
      if (!a.id) a.id = makeId("host");
      if (a.icon === undefined) a.icon = "";
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
        batteryAlerts: defaultBatteryAlertsConfig(),
        brandText: "",
        privateMode: false
      }
    };
  }
}

function saveDB() {
  ensureConfigStructure();
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), "utf8");
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
  loadDB,
  saveDB,
  sanitizeForClient,
  getDB
};
