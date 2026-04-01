import fs from "fs";
import path from "path";
import { DATA_FILE, ensureNormalizedDb, getDB, replaceDB, saveDB } from "./db.js";
import { audit, getRequestSource } from "./logger.js";

function validateConfigShape(input) {
  const errors = [];
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {
      ok: false,
      errors: ["Config root must be a JSON object."]
    };
  }

  const arrayFields = ["services", "links", "wol", "hostActions"];
  for (const field of arrayFields) {
    if (field in input && !Array.isArray(input[field])) {
      errors.push(`Field "${field}" must be an array if present.`);
    }
  }

  const objectFields = ["config", "admin"];
  for (const field of objectFields) {
    if (field in input && (!input[field] || typeof input[field] !== "object" || Array.isArray(input[field]))) {
      errors.push(`Field "${field}" must be an object if present.`);
    }
  }

  return { ok: errors.length === 0, errors };
}

function buildBackupFilePath(date = new Date()) {
  const stamp = [
    date.getFullYear(),
    String(date.getMonth() + 1).padStart(2, "0"),
    String(date.getDate()).padStart(2, "0"),
    "-",
    String(date.getHours()).padStart(2, "0"),
    String(date.getMinutes()).padStart(2, "0"),
    String(date.getSeconds()).padStart(2, "0")
  ].join("");

  return path.join(path.dirname(DATA_FILE), `${stamp}-wadph-data.json`);
}

function exportConfigSnapshot() {
  return ensureNormalizedDb(getDB());
}

function importConfigObject(nextConfig, { req } = {}) {
  const validation = validateConfigShape(nextConfig);
  if (!validation.ok) {
    return {
      ok: false,
      error: "invalid_structure",
      message: validation.errors.join(" ")
    };
  }

  const normalized = ensureNormalizedDb(nextConfig);
  const previous = JSON.parse(JSON.stringify(getDB()));
  let backupPath = null;

  try {
    if (fs.existsSync(DATA_FILE)) {
      backupPath = buildBackupFilePath();
      fs.renameSync(DATA_FILE, backupPath);
    }

    replaceDB(normalized);
    saveDB();

    audit(
      "config.import",
      "Configuration imported successfully",
      req ? getRequestSource(req) : null,
      { backupFile: backupPath ? path.basename(backupPath) : null }
    );

    return {
      ok: true,
      backupFile: backupPath ? path.basename(backupPath) : null,
      data: normalized
    };
  } catch (err) {
    replaceDB(previous);
    if (backupPath && !fs.existsSync(DATA_FILE) && fs.existsSync(backupPath)) {
      fs.renameSync(backupPath, DATA_FILE);
    }
    return {
      ok: false,
      error: "import_failed",
      message: err && err.message ? err.message : "Import failed"
    };
  }
}

export {
  exportConfigSnapshot,
  importConfigObject,
  validateConfigShape
};
