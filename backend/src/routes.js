import { exportConfigSnapshot, importConfigObject } from "./config.js";
import { audit, error as logError, getRequestSource, readRecentLogs } from "./logger.js";

export function registerAppRoutes(app, { authApi, dbApi, healthApi, actionsApi }) {
  const db = dbApi.getDB();
  const saveDB = dbApi.saveDB;
  const makeId = dbApi.makeId;
  const ensureConfigStructure = dbApi.ensureConfigStructure;
  const sanitizeBrandText = dbApi.sanitizeBrandText;
  const getBrandTextConfig = dbApi.getBrandTextConfig;
  const sanitizeForClient = dbApi.sanitizeForClient;

  const { requireAdmin, requireViewAccess, getSession } = authApi;
  const { healthCheckAll, pollHostInfoOnce } = healthApi;
  const { executeWOLTask, executeSSHAction, executeHostAction } = actionsApi;

  // -----------------------
  // Brand text endpoints
  // -----------------------
  app.get("/api/brand-text", requireViewAccess, (req, res) => {
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
  // Read-only state
  // -----------------------
  app.get("/api/state", requireViewAccess, (req, res) => {
    const isAdmin = !!getSession(req);
    res.json(sanitizeForClient(isAdmin));
  });

  // -----------------------
  // Manual refresh endpoint
  // -----------------------
  app.post("/api/refresh", requireViewAccess, async (req, res) => {
    try {
      await healthCheckAll();
      await pollHostInfoOnce();
      res.json({ ok: true });
    } catch (e) {
      logError("refresh error", e);
      res.status(500).json({ ok: false, error: "refresh_failed" });
    }
  });

  app.get("/api/config/export", requireAdmin, (req, res) => {
    const snapshot = exportConfigSnapshot();
    audit("config.export", "Configuration exported", getRequestSource(req));
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="wadboard-config-${new Date().toISOString().replace(/[:.]/g, "-")}.json"`);
    res.send(JSON.stringify(snapshot, null, 2));
  });

  app.post("/api/config/import", requireAdmin, (req, res) => {
    const result = importConfigObject(req.body, { req });
    if (!result.ok) {
      return res.status(result.error === "invalid_structure" ? 400 : 500).json(result);
    }
    return res.json({
      ok: true,
      backupFile: result.backupFile,
      state: sanitizeForClient(true)
    });
  });

  app.get("/api/logs", requireAdmin, (req, res) => {
    const limit = Number(req.query.limit) || 200;
    res.json({
      ok: true,
      lines: readRecentLogs(limit)
    });
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
    audit("service.create", `Service created: ${newSvc.name}`, getRequestSource(req), { id: newSvc.id });
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
    audit("service.update", `Service updated: ${svc.name || id}`, getRequestSource(req), { id });
    res.json(svc);
  });

  app.delete("/api/service/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    db.services = db.services.filter(s => s.id !== id);
    saveDB();
    audit("service.delete", `Service deleted: ${id}`, getRequestSource(req), { id });
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
    audit("link.create", `Link created: ${newLink.title}`, getRequestSource(req), { id: newLink.id });
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
    audit("link.update", `Link updated: ${lnk.title || id}`, getRequestSource(req), { id });
    res.json(lnk);
  });

  app.delete("/api/link/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    db.links = db.links.filter(l => l.id !== id);
    saveDB();
    audit("link.delete", `Link deleted: ${id}`, getRequestSource(req), { id });
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
    const { name, type, notes, sshActions, statusMethod, statusTarget } = req.body || {};
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
          icon: (a.icon || "").trim(),
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
      statusMethod: (statusMethod === "ping" || statusMethod === "http") ? statusMethod : "http",
      statusTarget: (statusTarget || "").trim(),
      lastStatus: "unknown",
      lastChecked: null,
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
    audit("wol.create", `WOL task created: ${task.name}`, getRequestSource(req), { id: task.id, type: task.type });
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
    statusMethod,
    statusTarget,
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
    if (statusMethod !== undefined) {
      task.statusMethod = (statusMethod === "ping" || statusMethod === "http") ? statusMethod : "http";
    }
    if (statusTarget !== undefined) task.statusTarget = String(statusTarget).trim();

    if (sshActions !== undefined) {
      if (Array.isArray(sshActions)) {
        task.sshActions = sshActions
          .map(a => ({
            id: makeId("ssh"),
            label: (a.label || "").trim(),
            icon: (a.icon || "").trim(),
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
    audit("wol.update", `WOL task updated: ${task.name || id}`, getRequestSource(req), { id, type: task.type });
    res.json(task);
  });

  app.delete("/api/wol/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    db.wol = db.wol.filter(a => a.id !== id);
    saveDB();
    audit("wol.delete", `WOL task deleted: ${id}`, getRequestSource(req), { id });
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

    const result = await executeWOLTask(task, { source: getRequestSource(req) });
    res.json(result);
  });

  app.post("/api/wol/:id/ssh/:actionId/run", requireAdmin, async (req, res) => {
    const { id, actionId } = req.params;
    const task = db.wol.find(a => a.id === id);
    if (!task) return res.status(404).json({ error: "WOL task not found" });

    const actions = Array.isArray(task.sshActions) ? task.sshActions : [];
    const action = actions.find(a => a.id === actionId);
    if (!action) return res.status(404).json({ error: "SSH action not found" });

    const result = await executeSSHAction(task, action, { source: getRequestSource(req) });
    res.json(result);
  });

  // -----------------------
  // Host actions CRUD / RUN
  // -----------------------
  app.post("/api/host-action", requireAdmin, (req, res) => {
    const { label, icon, command, notes } = req.body || {};
    if (!label || !command) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const newAction = {
      id: makeId("host"),
      label: label.trim(),
      icon: (icon || "").trim(),
      command: command.trim(),
      notes: (notes || "").trim(),
      lastRun: null,
      lastResult: "never"
    };

    db.hostActions.push(newAction);
    saveDB();
    audit("host-action.create", `Host action created: ${newAction.label}`, getRequestSource(req), { id: newAction.id });
    res.json(newAction);
  });

  app.put("/api/host-action/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    const action = db.hostActions.find(a => a.id === id);
    if (!action) return res.status(404).json({ error: "Host action not found" });

    const { label, icon, command, notes } = req.body || {};
    if (label   !== undefined) action.label   = String(label).trim();
    if (icon    !== undefined) action.icon    = String(icon).trim();
    if (command !== undefined) action.command = String(command).trim();
    if (notes   !== undefined) action.notes   = String(notes).trim();

    saveDB();
    audit("host-action.update", `Host action updated: ${action.label || id}`, getRequestSource(req), { id });
    res.json(action);
  });

  app.delete("/api/host-action/:id", requireAdmin, (req, res) => {
    const { id } = req.params;
    db.hostActions = db.hostActions.filter(a => a.id !== id);
    saveDB();
    audit("host-action.delete", `Host action deleted: ${id}`, getRequestSource(req), { id });
    res.json({ ok: true });
  });

  app.post("/api/host-action/:id/run", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const action = db.hostActions.find(a => a.id === id);
    if (!action) return res.status(404).json({ error: "Host action not found" });

    const result = await executeHostAction(action, { source: getRequestSource(req) });
    res.json(result);
  });


}
