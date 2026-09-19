import crypto from "crypto";
import { audit, getRequestSource } from "./logger.js";

export function createAuthModule({ dbApi }) {
  const db = dbApi.getDB();
  const checkPassword = dbApi.checkPassword;
  const hashPassword = dbApi.hashPassword;
  const ensureConfigStructure = dbApi.ensureConfigStructure;
  const saveDB = dbApi.saveDB;

  // -----------------------
  // Session store (in-memory)
  // -----------------------
  const sessions = {}; // { token: { createdAt: number } }
  const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
  const VIEW_SESSIONS = {}; // { token: { createdAt, lastSeenAt, ip, userAgent, acceptLanguage } }
  const VIEW_SESSION_TTL_MS = 180 * 24 * 60 * 60 * 1000; // 180 days

  function createSession() {
    const token = crypto.randomBytes(32).toString("hex");
    sessions[token] = { createdAt: Date.now() };
    return token;
  }

  // Called after a password rotation so a stolen/old admin cookie cannot keep
  // working past the change. The session that just performed the change is kept.
  function invalidateOtherSessions(currentToken, { stopTerminal } = {}) {
    for (const token of Object.keys(sessions)) {
      if (token === currentToken) continue;
      delete sessions[token];
      if (typeof stopTerminal === "function") {
        stopTerminal(token, "password_changed");
      }
    }
  }

  function createViewSession(req) {
    const token = crypto.randomBytes(32).toString("hex");
    const now = Date.now();
    VIEW_SESSIONS[token] = {
      createdAt: now,
      lastSeenAt: now,
      ip: getClientIp(req),
      userAgent: String(req && req.headers && req.headers["user-agent"] ? req.headers["user-agent"] : ""),
      acceptLanguage: String(req && req.headers && req.headers["accept-language"] ? req.headers["accept-language"] : "")
    };
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

  function getSessionByToken(token) {
    if (!token) return null;
    const sess = sessions[token];
    if (!sess) return null;
    if (Date.now() - sess.createdAt > SESSION_TTL_MS) {
      delete sessions[token];
      return null;
    }
    return { token, createdAt: sess.createdAt };
  }

  function getViewSession(req) {
    const token = req.cookies.viewToken;
    if (!token) return null;
    const sess = VIEW_SESSIONS[token];
    if (!sess) return null;
    if (Date.now() - sess.createdAt > VIEW_SESSION_TTL_MS) {
      delete VIEW_SESSIONS[token];
      return null;
    }
    sess.lastSeenAt = Date.now();
    return { token, ...sess };
  }

  // `req.ip` (and `req.secure`) are only trustworthy once Express is told which
  // hops to trust via `app.set("trust proxy", ...)` (see server.js / TRUST_PROXY
  // env var). With trust proxy left at its safe default (off), Express ignores
  // client-supplied `X-Forwarded-For`/`X-Forwarded-Proto` headers entirely, so
  // callers can no longer spoof their IP to dodge the login lock-out below or to
  // poison the audit log.
  function getClientIp(req) {
    const raw = req.ip || req.socket?.remoteAddress || "unknown";
    return String(raw).replace(/^::ffff:/, "");
  }

  function cleanupExpiredViewSessions() {
    const now = Date.now();
    for (const [token, sess] of Object.entries(VIEW_SESSIONS)) {
      if (!sess || now - sess.createdAt > VIEW_SESSION_TTL_MS) {
        delete VIEW_SESSIONS[token];
      }
    }
  }

  function parseBrowserFromUA(uaRaw) {
    const ua = String(uaRaw || "");
    if (!ua) return "Unknown browser";
    if (ua.includes("Edg/")) return "Microsoft Edge";
    if (ua.includes("OPR/") || ua.includes("Opera")) return "Opera";
    if (ua.includes("Chrome/") && !ua.includes("Edg/")) return "Chrome";
    if (ua.includes("Firefox/")) return "Firefox";
    if (ua.includes("Safari/") && ua.includes("Version/") && !ua.includes("Chrome/")) return "Safari";
    return "Unknown browser";
  }

  function parseOsFromUA(uaRaw) {
    const ua = String(uaRaw || "");
    if (!ua) return "Unknown OS";
    if (ua.includes("Windows NT")) return "Windows";
    if (ua.includes("Android")) return "Android";
    if (ua.includes("iPhone") || ua.includes("iPad")) return "iOS";
    if (ua.includes("Mac OS X")) return "macOS";
    if (ua.includes("Linux")) return "Linux";
    return "Unknown OS";
  }

  // -----------------------
  // Per-IP login throttling, shared by any endpoint that checks a password.
  // -----------------------
  function createAttemptLimiter({ maxAttempts, lockMs }) {
    const state = {}; // { ip: { count, lockedUntil } }

    function getState(req) {
      const ip = getClientIp(req);
      if (!state[ip]) state[ip] = { count: 0, lockedUntil: 0 };
      return state[ip];
    }

    function getRemainingMs(req) {
      const s = getState(req);
      const now = Date.now();
      if (s.lockedUntil > now) return s.lockedUntil - now;
      if (s.lockedUntil) s.lockedUntil = 0;
      return 0;
    }

    function registerFailure(req) {
      const s = getState(req);
      const now = Date.now();
      if (s.lockedUntil > now) return;
      s.count += 1;
      if (s.count >= maxAttempts) {
        s.count = 0;
        s.lockedUntil = now + lockMs;
      }
    }

    function clearFailures(req) {
      const s = getState(req);
      s.count = 0;
      s.lockedUntil = 0;
    }

    return { getRemainingMs, registerFailure, clearFailures };
  }

  // Private-mode ("view") access password.
  const accessLoginLimiter = createAttemptLimiter({ maxAttempts: 10, lockMs: 5 * 60 * 1000 });
  // Admin password — guards full RCE (terminal/host actions), so it gets a
  // stricter limiter than the plain viewer gate.
  const adminLoginLimiter = createAttemptLimiter({ maxAttempts: 5, lockMs: 15 * 60 * 1000 });

  function setViewAccessCookie(req, res, token) {
    res.cookie("viewToken", token, {
      httpOnly: true,
      sameSite: "strict",
      maxAge: VIEW_SESSION_TTL_MS,
      secure: !!req.secure
    });
  }

  function clearViewAccessCookie(req, res) {
    res.clearCookie("viewToken", {
      sameSite: "strict",
      secure: !!req.secure
    });
  }

  function requireAdmin(req, res, next) {
    const s = getSession(req);
    if (!s) {
      return res.status(401).json({ error: "unauthorized" });
    }
    req.sessionToken = s.token;
    next();
  }

  function isPrivateModeEnabled() {
    ensureConfigStructure();
    return !!db.config.privateMode;
  }

  function hasViewAccess(req) {
    if (!isPrivateModeEnabled()) return true;
    return !!getViewSession(req);
  }

  function requireViewAccess(req, res, next) {
    if (!hasViewAccess(req)) {
      return res.status(401).json({ error: "access_required" });
    }
    next();
  }

  function registerRoutes(app, { terminalApi } = {}) {
    const stopTerminalSessionByToken = terminalApi?.stopTerminalSessionByToken || (() => {});

    app.get("/api/access/status", (req, res) => {
      const privateMode = isPrivateModeEnabled();
      const authorized = privateMode ? !!getViewSession(req) : true;
      res.json({ privateMode, authorized });
    });

    app.post("/api/access/login", (req, res) => {
      const waitMs = accessLoginLimiter.getRemainingMs(req);
      if (waitMs > 0) {
        return res.status(429).json({
          error: "too_many_attempts",
          retryAfterSec: Math.ceil(waitMs / 1000)
        });
      }

      const { password } = req.body || {};
      if (!password || !checkPassword(password)) {
        accessLoginLimiter.registerFailure(req);
        const nowWaitMs = accessLoginLimiter.getRemainingMs(req);
        if (nowWaitMs > 0) {
          return res.status(429).json({
            error: "too_many_attempts",
            retryAfterSec: Math.ceil(nowWaitMs / 1000)
          });
        }
        return res.status(401).json({ error: "bad_password" });
      }

      accessLoginLimiter.clearFailures(req);
      const token = createViewSession(req);
      setViewAccessCookie(req, res, token);
      audit("access.login", "Private-mode access granted", getRequestSource(req, { viewToken: token }));
      return res.json({ ok: true });
    });

    app.post("/api/access/logout", (req, res) => {
      const token = req.cookies.viewToken;
      if (token) {
        delete VIEW_SESSIONS[token];
      }
      clearViewAccessCookie(req, res);
      audit("access.logout", "Private-mode session logged out", getRequestSource(req));
      return res.json({ ok: true });
    });

    app.put("/api/access/mode", requireAdmin, (req, res) => {
      ensureConfigStructure();
      const privateMode = !!(req.body && req.body.privateMode);
      db.config.privateMode = privateMode;
      saveDB();

      if (privateMode) {
        const token = createViewSession(req);
        setViewAccessCookie(req, res, token);
      } else {
        const token = req.cookies.viewToken;
        if (token) delete VIEW_SESSIONS[token];
        clearViewAccessCookie(req, res);
      }

      audit("access.mode", `Private mode ${privateMode ? "enabled" : "disabled"}`, getRequestSource(req), { privateMode });
      res.json({ ok: true, privateMode, authorized: true });
    });

    app.get("/api/access/sessions", requireAdmin, (req, res) => {
      cleanupExpiredViewSessions();
      const currentToken = String(req.cookies.viewToken || "");
      const sessions = Object.entries(VIEW_SESSIONS)
        .map(([token, sess]) => ({
          token,
          tokenPreview: `${token.slice(0, 8)}...${token.slice(-6)}`,
          current: token === currentToken,
          createdAt: sess.createdAt,
          lastSeenAt: sess.lastSeenAt || sess.createdAt,
          ip: sess.ip || "unknown",
          browser: parseBrowserFromUA(sess.userAgent),
          os: parseOsFromUA(sess.userAgent),
          userAgent: String(sess.userAgent || ""),
          language: String(sess.acceptLanguage || "").split(",")[0] || ""
        }))
        .sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0));

      res.json({
        ok: true,
        privateMode: isPrivateModeEnabled(),
        sessions
      });
    });

    app.delete("/api/access/sessions/:token", requireAdmin, (req, res) => {
      cleanupExpiredViewSessions();
      const token = String(req.params.token || "");
      const currentToken = String(req.cookies.viewToken || "");
      if (!token || !VIEW_SESSIONS[token]) {
        return res.status(404).json({ error: "session_not_found" });
      }

      delete VIEW_SESSIONS[token];
      if (token === currentToken) {
        clearViewAccessCookie(req, res);
        return res.json({ ok: true, revokedCurrent: true });
      }
      return res.json({ ok: true, revokedCurrent: false });
    });

    app.post("/api/access/sessions/revoke-others", requireAdmin, (req, res) => {
      cleanupExpiredViewSessions();
      const currentToken = String(req.cookies.viewToken || "");
      for (const token of Object.keys(VIEW_SESSIONS)) {
        if (!currentToken || token !== currentToken) {
          delete VIEW_SESSIONS[token];
        }
      }
      return res.json({ ok: true });
    });

    // -----------------------
    // Auth endpoints
    // -----------------------
    app.post("/api/login", (req, res) => {
      const waitMs = adminLoginLimiter.getRemainingMs(req);
      if (waitMs > 0) {
        return res.status(429).json({
          error: "too_many_attempts",
          retryAfterSec: Math.ceil(waitMs / 1000)
        });
      }

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
          adminLoginLimiter.registerFailure(req);
          const nowWaitMs = adminLoginLimiter.getRemainingMs(req);
          if (nowWaitMs > 0) {
            return res.status(429).json({
              error: "too_many_attempts",
              retryAfterSec: Math.ceil(nowWaitMs / 1000)
            });
          }
          return res.status(401).json({ error: "bad_password" });
        }
        adminLoginLimiter.clearFailures(req);
      }



      const token = createSession();

      res.cookie("adminToken", token, {
        httpOnly: true,
        sameSite: "strict",
        maxAge: SESSION_TTL_MS,
        secure: !!req.secure
      });

      if (isPrivateModeEnabled()) {
        const viewToken = createViewSession(req);
        setViewAccessCookie(req, res, viewToken);
      }

      audit("admin.login", db.admin.initialized ? "Admin session created" : "Admin password initialized", getRequestSource(req, { adminToken: token }));
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
      invalidateOtherSessions(req.sessionToken, { stopTerminal: stopTerminalSessionByToken });
      audit("admin.password.change", "Admin password updated; other sessions revoked", getRequestSource(req));

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
        stopTerminalSessionByToken(token, "logout");
      }

      res.clearCookie("adminToken", {
        sameSite: "strict",
        secure: !!req.secure
      });

      audit("admin.logout", "Admin session logged out", getRequestSource(req));
      return res.json({ ok: true });
    });


  }

  return {
    createSession,
    createViewSession,
    getSession,
    getSessionByToken,
    getViewSession,
    cleanupExpiredViewSessions,
    requireAdmin,
    requireViewAccess,
    hasViewAccess,
    isPrivateModeEnabled,
    setViewAccessCookie,
    clearViewAccessCookie,
    registerRoutes
  };
}
