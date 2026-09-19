import os from "os";
import { exec } from "child_process";

export function isAndroidLike() {
  const platform = String(process.platform || "");
  const release = String(process.release?.name || "");
  return !!(
    platform === "android" ||
    /android/i.test(release) ||
    process.env.ANDROID_ROOT ||
    process.env.ANDROID_DATA ||
    (typeof os.release === "function" && String(os.release()).toLowerCase().includes("android"))
  );
}

export function execCmd(cmd, { timeoutMs = 2000 } = {}) {
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
