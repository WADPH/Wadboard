import fs from "fs";
import { spawn } from "child_process";

export function createTerminalModule({ authApi }) {
  const TERMUX_SHELL_BIN = "/data/data/com.termux/files/usr/bin/bash";

  function isAndroidLike() {
    const platform = String(process.platform || "");
    const release = String(process.release?.name || "");
    return platform === "android" || /android/i.test(release) || !!process.env.ANDROID_ROOT;
  }

  const TERMINAL_IDLE_MS = 15 * 60 * 1000;
  const TERMINAL_IDLE_CHECK_MS = 15000;
  const TERMINAL_BUFFER_MAX = 200000;

  const terminalSessions = new Map();

  function parseCookieHeader(value) {
    const out = {};
    if (!value) return out;
    value.split(";").forEach(part => {
      const idx = part.indexOf("=");
      if (idx === -1) return;
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    });
    return out;
  }

  function resolveShellPath() {
    const candidates = [];
    if (process.env.SHELL) candidates.push(process.env.SHELL);
    if (isAndroidLike()) candidates.push(TERMUX_SHELL_BIN);
    candidates.push("/bin/bash", "/bin/sh");
    for (const c of candidates) {
      if (c && fs.existsSync(c)) return c;
    }
    return null;
  }

  function resolveScriptPath() {
    const candidates = [
      process.env.SCRIPT,
      "/data/data/com.termux/files/usr/bin/script",
      "/usr/bin/script",
      "/bin/script"
    ].filter(Boolean);
    for (const c of candidates) {
      if (c && fs.existsSync(c)) return c;
    }
    return null;
  }

  function getTerminalCapability() {
    const shellPath = resolveShellPath();
    if (!shellPath) {
      return {
        ok: false,
        missing: "shell",
        hint: isAndroidLike()
          ? "Install bash or set SHELL to a valid shell path"
          : "Install bash/sh or set SHELL to a valid shell path"
      };
    }
    const scriptPath = resolveScriptPath();
    if (!scriptPath) {
      return {
        ok: false,
        missing: "script",
        hint: isAndroidLike()
          ? "Install util-linux: pkg install util-linux"
          : "Install util-linux (script)"
      };
    }
    return { ok: true };
  }

  function isTerminalExpired(session) {
    if (!session) return true;
    return Date.now() - session.lastActivity > TERMINAL_IDLE_MS;
  }

  function touchTerminal(session) {
    if (session) session.lastActivity = Date.now();
  }

  function stopTerminalSession(session, reason) {
    if (!session) return;
    const { shellProcess, timer, clients, token } = session;
    if (timer) clearInterval(timer);
    try {
      shellProcess.kill();
    } catch {
      // ignore
    }
    if (clients && clients.size) {
      const msg = JSON.stringify({ type: "closed", reason: reason || "closed" });
      for (const ws of clients) {
        try {
          if (ws.readyState === 1) ws.send(msg);
          ws.close(1000, "closed");
        } catch {
          // ignore
        }
      }
    }
    terminalSessions.delete(token);
  }

  function ensureTerminalSession(token) {
    const existing = terminalSessions.get(token);
    if (existing && !isTerminalExpired(existing)) return existing;
    if (existing && isTerminalExpired(existing)) {
      stopTerminalSession(existing, "idle");
    }

    const shellPath = resolveShellPath();
    if (!shellPath) return null;
    const env = { ...process.env, TERM: "xterm-256color" };
    const cwd = process.env.HOME || process.cwd();
    const cap = getTerminalCapability();
    if (!cap.ok) return null;
    const scriptPath = resolveScriptPath();
    let shellProcess = null;
    let usingScript = true;

    try {
      shellProcess = spawn(scriptPath, ["-q", "/dev/null", "-c", shellPath], {
        cwd,
        env,
        stdio: "pipe"
      });
    } catch {
      usingScript = false;
    }

    if (!shellProcess) {
      usingScript = false;
      shellProcess = spawn(shellPath, [], { cwd, env, stdio: "pipe" });
    }

    const session = {
      shellProcess,
      lastActivity: Date.now(),
      clients: new Set(),
      timer: null,
      usingScript,
      buffer: "",
      token
    };

    shellProcess.on("error", err => {
      console.error("terminal shell error:", err && err.message ? err.message : err);
      stopTerminalSession(session, "error");
    });

    const appendBuffer = chunk => {
      if (!session) return;
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      session.buffer += text;
      if (session.buffer.length > TERMINAL_BUFFER_MAX) {
        session.buffer = session.buffer.slice(-TERMINAL_BUFFER_MAX);
      }
    };

    shellProcess.stdout?.on("data", data => {
      touchTerminal(session);
      appendBuffer(data);
      if (!session) return;
      for (const ws of session.clients) {
        if (ws.readyState === 1) ws.send(data);
      }
    });

    shellProcess.stderr?.on("data", data => {
      touchTerminal(session);
      appendBuffer(data);
      if (!session) return;
      for (const ws of session.clients) {
        if (ws.readyState === 1) ws.send(data);
      }
    });

    shellProcess.on("exit", () => {
      stopTerminalSession(session, "exit");
    });

    session.timer = setInterval(() => {
      if (isTerminalExpired(session)) {
        stopTerminalSession(session, "idle");
      }
    }, TERMINAL_IDLE_CHECK_MS);

    terminalSessions.set(token, session);
    return session;
  }

  function getTerminalSessionByToken(token) {
    if (!token) return null;
    const session = terminalSessions.get(token);
    if (session && isTerminalExpired(session)) {
      stopTerminalSession(session, "idle");
      return null;
    }
    return session;
  }

  function stopTerminalSessionByToken(token, reason) {
    const session = terminalSessions.get(token);
    if (session) stopTerminalSession(session, reason);
  }

  function registerRoutes(app) {
    const { requireAdmin } = authApi;

    app.get("/api/terminal/status", requireAdmin, (req, res) => {
      const cap = getTerminalCapability();
      res.json(cap);
    });

  }

  function attachWebSocket(wss) {
    const { getSessionByToken } = authApi;

    wss.on("connection", (ws, req) => {
      const cookies = parseCookieHeader(req.headers.cookie || "");
      const token = cookies.adminToken;
      const adminSession = getSessionByToken(token);
      const cap = getTerminalCapability();
      let terminalSession = getTerminalSessionByToken(token);

      if (!cap.ok) {
        ws.close(1011, "terminal_unavailable");
        return;
      }

      if (!adminSession && (!terminalSession || isTerminalExpired(terminalSession))) {
        ws.close(4401, "auth_required");
        return;
      }

      if (!terminalSession || isTerminalExpired(terminalSession)) {
        if (!adminSession) {
          ws.close(4401, "auth_required");
          return;
        }
        const sess = ensureTerminalSession(token);
        if (!sess) {
          ws.close(1011, "terminal_unavailable");
          return;
        }
        terminalSession = sess;
      }

      if (!terminalSession) {
        ws.close(1011, "terminal_unavailable");
        return;
      }

      terminalSession.clients.add(ws);
      ws.send(JSON.stringify({ type: "ready" }));
      if (terminalSession.buffer) {
        try {
          ws.send(Buffer.from(terminalSession.buffer, "utf8"));
        } catch {
          // ignore
        }
      }

      ws.on("message", (data, isBinary) => {
        if (!terminalSession) return;
        if (!isBinary) {
          const text = typeof data === "string" ? data : data.toString("utf8");
          try {
            const msg = JSON.parse(text);
            if (msg && msg.type === "close") {
              stopTerminalSession(terminalSession, "manual");
            }
          } catch {
            // ignore non-json
          }
          return;
        }

        if (Buffer.isBuffer(data)) {
          touchTerminal(terminalSession);
          try {
            terminalSession.shellProcess.stdin?.write(data);
          } catch {
            // ignore
          }
        } else if (data instanceof ArrayBuffer) {
          touchTerminal(terminalSession);
          try {
            terminalSession.shellProcess.stdin?.write(Buffer.from(data));
          } catch {
            // ignore
          }
        }
      });

      ws.on("close", () => {
        if (!terminalSession) return;
        terminalSession.clients.delete(ws);
        if (terminalSession.clients.size === 0) {
          terminalSession.lastActivity = Date.now();
        }
      });
    });
  }

  return {
    registerRoutes,
    attachWebSocket,
    stopTerminalSessionByToken
  };
}
