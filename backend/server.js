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
const healthApi = createHealthModule({ dbApi, cameraApi });
const terminalApi = createTerminalModule({ authApi });

const app = express();

// Off by default: without a reverse proxy in front of Wadboard, trusting
// X-Forwarded-For/X-Forwarded-Proto would let any client spoof its IP (bypassing
// login lock-outs and poisoning the audit log) or fake an HTTPS connection
// (making cookies think they're safe to send unencrypted). Set TRUST_PROXY=1
// only when Wadboard sits behind a reverse proxy/tunnel that sets those headers.
const TRUST_PROXY = process.env.TRUST_PROXY;
if (TRUST_PROXY) {
  app.set("trust proxy", TRUST_PROXY === "1" ? 1 : TRUST_PROXY);
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://unpkg.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
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
  app.use(express.static(FRONTEND_DIR));
  app.get(["/", "/health"], (req, res) => {
    res.sendFile(FRONTEND_INDEX);
  });
}

authApi.registerRoutes(app, { terminalApi });
healthApi.registerRoutes(app, { authApi });
terminalApi.registerRoutes(app);
registerAppRoutes(app, { authApi, dbApi, healthApi, actionsApi, cameraApi });

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
