import fs from "fs";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import { fileURLToPath } from "url";
import { WebSocketServer } from "ws";
import * as dbApi from "./src/db.js";
import { createAuthModule } from "./src/auth.js";
import { createHealthModule } from "./src/health.js";
import { createActionsModule } from "./src/actions.js";
import { createCameraModule } from "./src/camera.js";
import { createTerminalModule } from "./src/terminal.js";
import { createIconsModule } from "./src/icons.js";
import { createNotificationsModule } from "./src/notifications.js";
import { registerAppRoutes } from "./src/routes.js";
import * as logger from "./src/logger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FRONTEND_DIR = path.join(__dirname, "..", "frontend");
const FRONTEND_INDEX = path.join(FRONTEND_DIR, "index.html");
const PORT = 4000;

dbApi.loadDB();

const authApi = createAuthModule({ dbApi });
const actionsApi = createActionsModule({ dbApi });
const cameraApi = createCameraModule({ dbApi });
const notificationsApi = createNotificationsModule({ dbApi, authApi });
const healthApi = createHealthModule({ dbApi, cameraApi, notificationsApi });
const terminalApi = createTerminalModule({ authApi });
const iconsApi = createIconsModule();

const app = express();

// X-Forwarded-For/X-Forwarded-Proto are only honoured when the connection comes
// from a proxy on this same host (nginx, Caddy, cloudflared, ...), so the real
// client IP reaches login lock-outs, the audit log and camera notifications.
// Clients connecting directly arrive from a non-loopback address, so their
// forwarded headers are ignored and cannot be used to spoof an IP or fake HTTPS.
// TRUST_PROXY overrides this: any Express "trust proxy" value (e.g. "1" or a
// proxy's address when it runs on another machine), or "0"/"false" to disable.
const TRUST_PROXY = String(process.env.TRUST_PROXY || "loopback").trim();
if (TRUST_PROXY !== "0" && TRUST_PROXY.toLowerCase() !== "false") {
  app.set("trust proxy", TRUST_PROXY === "1" ? 1 : TRUST_PROXY);
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      // Remote (Iconify) icons and icon search go through /api/icons on this
      // origin (see src/icons.js), so no third-party image/connect source is needed.
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'", "https://unpkg.com"],
      connectSrc: ["'self'", "ws:", "wss:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  // The xterm assets are pulled from unpkg.com without CORP/CORS headers of
  // their own; the stricter cross-origin isolation headers would block them.
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
  frameguard: { action: "deny" }
}));
app.use(express.json());
app.use(cookieParser());

if (fs.existsSync(FRONTEND_INDEX)) {
  // `no-cache` (not `no-store`) keeps ETag/Last-Modified conditional requests
  // working, but forces every hop — browser and any reverse proxy/tunnel in
  // front of Wadboard — to revalidate with this server instead of silently
  // serving a stale copy of app.js/styles.css after a deploy.
  const noCacheHeaders = (res) => res.setHeader("Cache-Control", "no-cache");

  app.use(express.static(FRONTEND_DIR, { setHeaders: noCacheHeaders }));
  app.get(["/", "/health"], (req, res) => {
    noCacheHeaders(res);
    res.sendFile(FRONTEND_INDEX);
  });
}

authApi.registerRoutes(app, { terminalApi });
healthApi.registerRoutes(app, { authApi });
terminalApi.registerRoutes(app);
iconsApi.registerRoutes(app, { authApi });
notificationsApi.registerRoutes(app);
registerAppRoutes(app, { authApi, dbApi, healthApi, actionsApi, cameraApi, notificationsApi });

healthApi.startMonitoring();

process.on("uncaughtException", err => {
  logger.error("uncaughtException", err);
});

process.on("unhandledRejection", reason => {
  logger.error("unhandledRejection", reason);
});

const server = app.listen(PORT, () => {
  logger.info("WADPH Dashboard API running", { port: PORT, logFile: logger.LOG_FILE });
});

const wss = new WebSocketServer({ server, path: "/api/terminal" });
terminalApi.attachWebSocket(wss);
