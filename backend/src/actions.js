import fetch from "node-fetch";
import { exec } from "child_process";
import { audit, error as logError } from "./logger.js";

export function createActionsModule({ dbApi }) {
  const db = dbApi.getDB();
  const saveDB = dbApi.saveDB;

  // -----------------------
  // WOL execution (MikroTik, Basic, PowerSW)
  // -----------------------

  function executeBasicWOL(task, context = {}) {
    return new Promise(resolve => {
      const mac = (task.mac || "").trim();
      if (!mac) {
        task.lastRun = new Date().toISOString();
        task.lastResult = "invalid_mac";
        saveDB();
        audit("wol.run", `WOL failed: ${task.name || task.id}`, context.source, { result: "invalid_mac" });
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
        audit("wol.run", `WOL ${okFlag ? "executed" : "failed"}: ${task.name || task.id}`, context.source, { result, detail });
        resolve({ ok: okFlag, result, detail });
      });
    });
  }


  async function executeWadEspPower(task, context = {}) {
    const host = (task.espHost || "").trim();
    if (!host) {
      task.lastRun = new Date().toISOString();
      task.lastResult = "invalid_esp_host";
      saveDB();
      audit("wol.run", `WadESP WOL failed: ${task.name || task.id}`, context.source, { result: "invalid_esp_host" });
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
        audit("wol.run", `WadESP WOL failed: ${task.name || task.id}`, context.source, { result: "http_" + res.status });
        return { ok: false, result: "http_" + res.status, detail: res.statusText || "ESP HTTP error" };
      }

      task.lastRun = new Date().toISOString();
      task.lastResult = "ok";
      saveDB();
      audit("wol.run", `WadESP WOL executed: ${task.name || task.id}`, context.source, { result: "ok" });
      return { ok: true, result: "ok" };
    } catch (e) {
      task.lastRun = new Date().toISOString();
      task.lastResult = "error";
      saveDB();
      logError("WadESP execution error", e);
      audit("wol.run", `WadESP WOL failed: ${task.name || task.id}`, context.source, { result: "error", detail: e && e.message ? e.message : e });
      return { ok: false, result: "error", detail: e && e.message ? e.message : "ESP request failed" };
    } finally {
      clearTimeout(timer);
    }
  }


  async function executeWOLTask(task, context = {}) {
    if (task.type === "basic") {
      return executeBasicWOL(task, context);
    }

    if (task.type === "wadesp") {
      return executeWadEspPower(task, context);
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
    audit("wol.run", `WOL ${okFlag ? "executed" : "failed"}: ${task.name || task.id}`, context.source, { result, detail });

    return { ok: okFlag, result, detail };
  }




  // -----------------------
  // SSH execution (generic)
  // -----------------------
  function escapeShellSingleQuotes(str) {
    return String(str).replace(/'/g, `'\\''`);
  }

  async function executeSSHAction(task, action, context = {}) {
    const host = (action.host || task.host || "").trim();
    const user = (action.user || "").trim();
    const pass = (action.pass || "").trim();
    const command = (action.command || "").trim();

    if (!host || !user || !command) {
      const result = "invalid_config";
      action.lastRun = new Date().toISOString();
      action.lastResult = result;
      saveDB();
      audit("ssh.run", `SSH action failed: ${action.label || action.id}`, context.source, { result });
      return { ok: false, result, detail: "Missing SSH host/user/command" };
    }

    // Password-based SSH requires sshpass to be installed on the host running Wadboard.
    if (pass) {
      const chk = await execCmd("sshpass -V", { timeoutMs: 1200 });
      if (!chk.ok) {
        const result = "missing_sshpass";
        const hint = isAndroidLike()
          ? "Для SSH по паролю нужен sshpass. Termux: pkg install sshpass"
          : "Для SSH по паролю нужен sshpass. Установите sshpass на хосте где запущен Wadboard (например: apt install sshpass)";
        action.lastRun = new Date().toISOString();
        action.lastResult = result;
        saveDB();
        audit("ssh.run", `SSH action failed: ${action.label || action.id}`, context.source, { result });
        return { ok: false, result, detail: hint };
      }
    }

    const safeCmd = escapeShellSingleQuotes(command);

    // If password is provided, use sshpass with env var (avoids leaking password in process args).
    const sshCmd = pass
      ? `sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 ${user}@${host} '${safeCmd}'`
      : `ssh -o BatchMode=yes -o ConnectTimeout=5 ${user}@${host} '${safeCmd}'`;

    const env = pass ? { ...process.env, SSHPASS: pass } : process.env;

    return await new Promise(resolve => {
      exec(sshCmd, { timeout: 10000, env }, (error, stdout, stderr) => {
        let result;
        let okFlag;
        let detail;
        if (error) {
          okFlag = false;
          result = "error";
          detail = stderr || error.message || "SSH command failed";
        } else {
          okFlag = true;
          result = "ok";
        }
        action.lastRun = new Date().toISOString();
        action.lastResult = result;
        saveDB();
        audit("ssh.run", `SSH action ${okFlag ? "executed" : "failed"}: ${action.label || action.id}`, context.source, { result, detail });
        resolve({ ok: okFlag, result, detail });
      });
    });
  }

  // -----------------------
  // Local host actions execution (Termux)
  // -----------------------
  const INFO_SCRIPT = "/data/data/com.termux/files/home/scripts/info.sh";
  const SHELL_BIN   = "/data/data/com.termux/files/usr/bin/bash";

  function executeHostAction(action, context = {}) {
    return new Promise(resolve => {
      const cmd = (action.command || "").trim();
      if (!cmd) {
        const result = "invalid_command";
        action.lastRun = new Date().toISOString();
        action.lastResult = result;
        saveDB();
        audit("host-action.run", `Host action failed: ${action.label || action.id}`, context.source, { result });
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
        audit("host-action.run", `Host action ${okFlag ? "executed" : "failed"}: ${action.label || action.id}`, context.source, { result, detail });
        resolve({ ok: okFlag, result, detail });
      });
    });
  }

  return {
    executeBasicWOL,
    executeWadEspPower,
    executeWOLTask,
    executeSSHAction,
    executeHostAction
  };
}
