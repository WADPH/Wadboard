import fs from "fs";
import path from "path";
import express from "express";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "url";
import { WebSocketServer } from "ws";
import * as dbApi from "./src/db.js";
import { createAuthModule } from "./src/auth.js";
import { createHealthModule } from "./src/health.js";
import { createActionsModule } from "./src/actions.js";
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
const healthApi = createHealthModule({ dbApi });
const terminalApi = createTerminalModule({ authApi });

const app = express();
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
registerAppRoutes(app, { authApi, dbApi, healthApi, actionsApi });

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
