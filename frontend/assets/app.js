// ==============================
  // CONFIG
  // ==============================
  const API_BASE = "/api";
  const THEME_KEY = "wadphTheme";

  let editMode = false;
  let state = { services: [], links: [], wol: [], hostActions: [] };
  let privateAccessMode = false;
  let viewAccessGranted = true;
  let appStarted = false;
  let isSyncingAccessSwitch = false;

  // modal mode for Add/Edit forms
  let mode = { type: "service", action: "create", id: null };

  // pending protected action to execute after password check (one-shot)
  let pendingAction = null;

  // ==============================
  // DOM refs
  // ==============================
  const overlay = document.getElementById("overlay");
  const openBtn = document.getElementById("open-modal");
  const closeBtn = document.getElementById("modal-close");

  const tabSvcBtn  = document.getElementById("tab-service");
  const tabLnkBtn  = document.getElementById("tab-link");
  const tabWolBtn  = document.getElementById("tab-wol");
  const tabHostBtn = document.getElementById("tab-host");

  const formSvc  = document.getElementById("form-service");
  const formLnk  = document.getElementById("form-link");
  const formWol  = document.getElementById("form-wol");
  const formHost = document.getElementById("form-host");

  const svcTitleEl   = document.getElementById("svc-form-title");
  const svcSubmitEl  = document.getElementById("svc-submit");
  const lnkTitleEl   = document.getElementById("lnk-form-title");
  const lnkSubmitEl  = document.getElementById("lnk-submit");
  const wolTitleEl   = document.getElementById("wol-form-title");
  const wolSubmitEl  = document.getElementById("wol-submit");
  const hostTitleEl  = document.getElementById("host-form-title");
  const hostSubmitEl = document.getElementById("host-submit");

  const svcGrid = document.getElementById("svc-grid");
  const lnkGrid = document.getElementById("lnk-grid");
  const wolGrid = document.getElementById("wol-grid");

  const svcCount = document.getElementById("svc-count");
  const lnkCount = document.getElementById("lnk-count");
  const wolCount = document.getElementById("wol-count");

  const adminToggleBtn = document.getElementById("admin-toggle");
  const adminToggleHealthBtn = document.getElementById("admin-toggle-health");
  const adminOverlay   = document.getElementById("admin-overlay");
  const adminCloseBtn  = document.getElementById("admin-close");
  const adminForm      = document.getElementById("admin-form");
  const adminPassInput = document.getElementById("admin-pass");
  const adminStatusEl  = document.getElementById("admin-status");
  const accessOverlay  = document.getElementById("access-overlay");
  const accessForm     = document.getElementById("access-form");
  const accessPassInput= document.getElementById("access-pass");
  const accessStatusEl = document.getElementById("access-status");

  const svcMethodEl      = document.getElementById("svc-method");
  const svcCheckLabelEl  = document.getElementById("svc-check-label");
  const svcCheckInputEl  = document.getElementById("svc-check");

  const refreshBtn       = document.getElementById("refresh-btn");
  const healthBtn        = document.getElementById("health-btn");

  const homePage         = document.getElementById("home-page");
  const healthPage       = document.getElementById("health-page");
  const healthHomeBtn    = document.getElementById("health-home-btn");
  const healthRefreshBtn = document.getElementById("health-refresh-btn");
  const healthThemeBtn   = document.getElementById("theme-toggle-health");
  const terminalBtn      = document.getElementById("terminal-toggle");
  const terminalHealthBtn= document.getElementById("terminal-toggle-health");

  const healthUpdatedEl  = document.getElementById("health-updated");
  const healthErrorEl    = document.getElementById("health-error");

  const healthHostnameEl = document.getElementById("health-hostname");
  const healthOsEl       = document.getElementById("health-os");
  const healthUptimeEl   = document.getElementById("health-uptime");
  const healthIpEl       = document.getElementById("health-ip");
  const healthBatteryEl  = document.getElementById("health-battery");

  const healthCpuRingEl  = document.getElementById("health-cpu-ring");
  const healthCpuPctEl   = document.getElementById("health-cpu-pct");
  const healthCpuLoadEl  = document.getElementById("health-cpu-load");
  const healthCpuNoteEl  = document.getElementById("health-cpu-note");

  const healthRamBarEl   = document.getElementById("health-ram-bar");
  const healthRamTextEl  = document.getElementById("health-ram-text");
  const healthRamNoteEl  = document.getElementById("health-ram-note");

  const healthDiskBarEl  = document.getElementById("health-disk-bar");
  const healthDiskTextEl = document.getElementById("health-disk-text");
  const healthDiskNoteEl = document.getElementById("health-disk-note");

  const healthSysNoteEl  = document.getElementById("health-sys-note");

  const isHealthRoute = window.location.pathname === "/health";

  const wolHostInput     = document.getElementById("wol-host");
  const wolSshList       = document.getElementById("wol-ssh-list");
  const wolSshAddBtn     = document.getElementById("wol-ssh-add");
  const wolCheckMethodEl = document.getElementById("wol-check-method");
  const wolCheckLabelEl  = document.getElementById("wol-check-label");
  const wolCheckInputEl  = document.getElementById("wol-check-target");

  const hostLabelInput   = document.getElementById("host-label");
  const hostIconInput    = document.getElementById("host-icon");
  const hostIconTrigger  = document.getElementById("host-icon-trigger");
  const hostCommandInput = document.getElementById("host-command");
  const hostNotesInput   = document.getElementById("host-notes");
  const iconPickerOverlay= document.getElementById("icon-picker-overlay");
  const iconPickerCloseBtn = document.getElementById("icon-picker-close");
  const iconPickerSearchInput = document.getElementById("icon-picker-search");
  const iconPickerStatusEl = document.getElementById("icon-picker-status");
  const iconPickerGrid   = document.getElementById("icon-picker-grid");

  const settingsOverlay       = document.getElementById("settings-overlay");
  const settingsCloseBtn      = document.getElementById("settings-close");
  const settingsSessionText   = document.getElementById("settings-session-text");
  const settingsLoginForm     = document.getElementById("settings-login-form");
  const settingsPassInput     = document.getElementById("settings-pass");
  const settingsLoginStatusEl = document.getElementById("settings-login-status");
  const settingsLogoutRow     = document.getElementById("settings-logout-row");
  const settingsLogoutBtn     = document.getElementById("settings-logout-btn");
  const accessPrivateEnabledInput = document.getElementById("access-private-enabled");
  const accessSaveStatus          = document.getElementById("access-save-status");
  const accessPublicLabel         = document.getElementById("access-public-label");
  const accessPrivateLabel        = document.getElementById("access-private-label");
  const viewLogoutBtn             = document.getElementById("view-logout-btn");
  const viewLogoutHealthBtn       = document.getElementById("view-logout-health-btn");
  const viewSessionsRefreshBtn    = document.getElementById("view-sessions-refresh-btn");
  const viewSessionsRevokeOthersBtn = document.getElementById("view-sessions-revoke-others-btn");
  const viewSessionsStatusEl      = document.getElementById("view-sessions-status");
  const viewSessionsListEl        = document.getElementById("view-sessions-list");

  const terminalOverlay   = document.getElementById("terminal-overlay");
  const terminalCloseBtn  = document.getElementById("terminal-close");
  const terminalKillBtn   = document.getElementById("terminal-kill");
  const terminalShellEl   = document.getElementById("terminal-shell");
  const terminalStatusEl  = document.getElementById("terminal-status");

  const brandTextInput        = document.getElementById("brand-text");
  const brandSaveBtn          = document.getElementById("brand-save-btn");
  const brandSaveStatus       = document.getElementById("brand-save-status");

  const batteryEnabledInput   = document.getElementById("battery-enabled");
  const batteryDisabledLabel  = document.getElementById("battery-disabled-label");
  const batteryEnabledLabel   = document.getElementById("battery-enabled-label");
  const batteryLevelsInput    = document.getElementById("battery-levels");
  const batteryBotTokenInput  = document.getElementById("battery-bot-token");
  const batteryChatIdInput    = document.getElementById("battery-chat-id");
  const batterySaveBtn        = document.getElementById("battery-save-btn");
  const batterySaveStatus     = document.getElementById("battery-save-status");
  const configExportBtn       = document.getElementById("config-export-btn");
  const configImportBtn       = document.getElementById("config-import-btn");
  const configImportInput     = document.getElementById("config-import-input");
  const configImportStatus    = document.getElementById("config-import-status");
  const viewLogsBtn           = document.getElementById("view-logs-btn");
  const logsOverlay           = document.getElementById("logs-overlay");
  const logsCloseBtn          = document.getElementById("logs-close");
  const logsRefreshBtn        = document.getElementById("logs-refresh-btn");
  const logsStatusEl          = document.getElementById("logs-status");
  const logsViewerEl          = document.getElementById("logs-viewer");

  // ==============================
  // THEME
  // ==============================
  function loadTheme() {
    const t = localStorage.getItem(THEME_KEY);
    return t === "light" || t === "dark" ? t : "dark";
  }
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem(THEME_KEY, t);
    applyTerminalTheme();
  }

  function buildTerminalTheme() {
    const styles = getComputedStyle(document.documentElement);
    const background = styles.getPropertyValue("--surface-alt").trim() || "#171923";
    const foreground = styles.getPropertyValue("--text-main").trim() || "#ecf0ff";
    const selection = styles.getPropertyValue("--drag-bg").trim() || "rgba(124,58,237,0.25)";
    return { background, foreground, cursor: foreground, selection };
  }

  function applyTerminalTheme() {
    if (terminalShellEl) {
      const styles = getComputedStyle(document.documentElement);
      terminalShellEl.style.background = styles.getPropertyValue("--surface-alt").trim();
    }
    if (window.termInstance) {
      window.termInstance.setOption("theme", buildTerminalTheme());
    }
  }
  applyTheme(loadTheme());
  syncSwitchLabelStates();

  function sanitizeBrandText(value) {
    const s = String(value == null ? "" : value);
    return s
      .replace(/[\r\n\t]+/g, " ")
      .replace(/[\u0000-\u001F\u007F]/g, "")
      .replace(/[<>]/g, "")
      .trim()
      .slice(0, 40);
  }

  let brandText = "WELCOME";
  let brandTextCustom = "";

  function applyBrandText() {
    document.querySelectorAll(".brand-mark").forEach(el => { el.textContent = brandText; });
  }

  function loadBrandTextIntoForm() {
    if (!brandTextInput) return;
    brandTextInput.value = brandTextCustom;
    if (brandSaveStatus) brandSaveStatus.textContent = "";
  }

  applyBrandText();

  async function refreshBrandTextFromServer() {
    const payload = await apiGET("/brand-text");
    if (payload && typeof payload.text === "string") {
      brandText = sanitizeBrandText(payload.text) || "WELCOME";
    } else {
      brandText = "WELCOME";
    }
    if (payload && typeof payload.custom === "string") {
      brandTextCustom = sanitizeBrandText(payload.custom);
    } else {
      brandTextCustom = "";
    }
    applyBrandText();
    loadBrandTextIntoForm();
  }

  function bindThemeToggle(btn) {
    if (!btn) return;
    btn.addEventListener("click", () => {
      const nextTheme =
        (document.documentElement.getAttribute("data-theme") === "dark")
        ? "light"
        : "dark";
      applyTheme(nextTheme);
    });
  }

  bindThemeToggle(document.getElementById("theme-toggle"));
  bindThemeToggle(healthThemeBtn);

  if (healthBtn) {
    healthBtn.addEventListener("click", () => {
      window.location.assign("/health");
    });
  }
  if (healthHomeBtn) {
    healthHomeBtn.addEventListener("click", () => {
      window.location.assign("/");
    });
  }

  if (terminalBtn) {
    terminalBtn.addEventListener("click", () => openTerminalModal(false));
  }
  if (terminalHealthBtn) {
    terminalHealthBtn.addEventListener("click", () => openTerminalModal(false));
  }
  if (terminalCloseBtn) {
    terminalCloseBtn.addEventListener("click", () => {
      if (terminalOverlay) terminalOverlay.classList.add("hidden");
      if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
        terminalSocket.close(1000, "ui_close");
      }
    });
  }
  if (terminalKillBtn) {
    terminalKillBtn.addEventListener("click", () => {
      terminalNeedsAuth = true;
      if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
        terminalSocket.send(JSON.stringify({ type: "close" }));
      }
      if (terminalStatusEl) terminalStatusEl.textContent = "Closing session...";
      if (terminalOverlay) terminalOverlay.classList.add("hidden");
    });
  }

  window.addEventListener("resize", () => {
    if (terminalOverlay && !terminalOverlay.classList.contains("hidden") && terminalFitAddon) {
      terminalFitAddon.fit();
    }
  });

  // ==============================
  // UTIL
  // ==============================
  // Toast notifications for action results + errors (replaces browser alerts)
  const toastStack = document.getElementById("toast-stack");

  const ICON_BTN_PLUS = `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path fill-rule="evenodd" d="M8 2a.5.5 0 0 1 .5.5v5h5a.5.5 0 0 1 0 1h-5v5a.5.5 0 0 1-1 0v-5h-5a.5.5 0 0 1 0-1h5v-5A.5.5 0 0 1 8 2"></path></svg><span class="sr-only">Add</span>`;
  const ICON_BTN_EDIT = `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M12.854.146a.5.5 0 0 0-.707 0L10.5 1.793 14.207 5.5l1.647-1.646a.5.5 0 0 0 0-.708zm.646 6.061L9.793 2.5 3.293 9H3.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.207zm-7.468 7.468A.5.5 0 0 1 6 13.5V13h-.5a.5.5 0 0 1-.5-.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.5-.5V10h-.5a.5.5 0 0 1-.175-.032l-.179.178a.5.5 0 0 0-.11.168l-2 5a.5.5 0 0 0 .65.65l5-2a.5.5 0 0 0 .168-.11z"/></svg><span class="sr-only">Edit</span>`;
  const ICON_BTN_DELETE = `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M2.5 1a1 1 0 0 0-1 1v1a1 1 0 0 0 1 1H3v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V4h.5a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H10a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1zm3 4a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 .5-.5M8 5a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7A.5.5 0 0 1 8 5m3 .5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 1 0"/></svg><span class="sr-only">Delete</span>`;
  const ACTION_ICON_OPTIONS = [
    { key: "", label: "No icon" },
    { key: "external-link", label: "External Link", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M10.5 1a.5.5 0 0 0 0 1h2.793L8.146 7.146a.5.5 0 1 0 .708.708L14 2.707V5.5a.5.5 0 0 0 1 0v-4A.5.5 0 0 0 14.5 1z"></path><path d="M13.5 14h-11A1.5 1.5 0 0 1 1 12.5v-9A1.5 1.5 0 0 1 2.5 2H7a.5.5 0 0 1 0 1H2.5a.5.5 0 0 0-.5.5v9a.5.5 0 0 0 .5.5h11a.5.5 0 0 0 .5-.5V8a.5.5 0 0 1 1 0v4.5a1.5 1.5 0 0 1-1.5 1.5"></path></svg>` },
    { key: "link", label: "Link", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6.354 5.5H4a3 3 0 0 0 0 6h2.5a3 3 0 0 0 2.83-2 .5.5 0 1 0-.94-.34A2 2 0 0 1 6.5 10.5H4a2 2 0 1 1 0-4h2.354a.5.5 0 1 0 0-1"></path><path d="M9.646 10.5H12a3 3 0 1 0 0-6H9.5a3 3 0 0 0-2.83 2 .5.5 0 1 0 .94.34A2 2 0 0 1 9.5 5.5H12a2 2 0 1 1 0 4H9.646a.5.5 0 1 0 0 1"></path><path d="M5.5 8a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1H6A.5.5 0 0 1 5.5 8"></path></svg>` },
    { key: "terminal", label: "Terminal", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1.5 3A1.5 1.5 0 0 1 3 1.5h10A1.5 1.5 0 0 1 14.5 3v10A1.5 1.5 0 0 1 13 14.5H3A1.5 1.5 0 0 1 1.5 13zm1.8 1.7a.5.5 0 0 0-.1.7L4.793 7 3.2 8.6a.5.5 0 0 0 .7.7l2-2a.5.5 0 0 0 0-.7l-2-2a.5.5 0 0 0-.7.1m3.7 4.8a.5.5 0 0 0 0 1h4a.5.5 0 0 0 0-1z"></path></svg>` },
    { key: "power", label: "Power", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7.5 1.5a.5.5 0 0 1 1 0v5a.5.5 0 0 1-1 0z"></path><path d="M5.03 3.97a.5.5 0 0 1 0 .707A4.5 4.5 0 1 0 10.97 4.68a.5.5 0 1 1 .707-.707A5.5 5.5 0 1 1 4.323 3.97a.5.5 0 0 1 .707 0"></path></svg>` },
    { key: "restart", label: "Restart", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 3a5 5 0 1 0 4.546 2.92.5.5 0 1 1 .908-.42A6 6 0 1 1 8 2a5.96 5.96 0 0 1 4.24 1.76V2.5a.5.5 0 0 1 1 0V5a.5.5 0 0 1-.5.5h-2.5a.5.5 0 0 1 0-1h1.36A4.96 4.96 0 0 0 8 3"></path></svg>` },
    { key: "play", label: "Play", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 2.5v11l9-5.5z"></path></svg>` },
    { key: "stop", label: "Stop", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 3h10v10H3z"></path></svg>` },
    { key: "gear", label: "Gear", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M9.405 1.05a1 1 0 0 0-1.81 0l-.35.79a1 1 0 0 1-1.17.55l-.85-.28a1 1 0 0 0-1.23 1.23l.28.85a1 1 0 0 1-.55 1.17l-.79.35a1 1 0 0 0 0 1.81l.79.35a1 1 0 0 1 .55 1.17l-.28.85a1 1 0 0 0 1.23 1.23l.85-.28a1 1 0 0 1 1.17.55l.35.79a1 1 0 0 0 1.81 0l.35-.79a1 1 0 0 1 1.17-.55l.85.28a1 1 0 0 0 1.23-1.23l-.28-.85a1 1 0 0 1 .55-1.17l.79-.35a1 1 0 0 0 0-1.81l-.79-.35a1 1 0 0 1-.55-1.17l.28-.85a1 1 0 0 0-1.23-1.23l-.85.28a1 1 0 0 1-1.17-.55zM8.5 10.5a2.5 2.5 0 1 1 0-5 2.5 2.5 0 0 1 0 5"></path></svg>` },
    { key: "wrench", label: "Wrench", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M9.41 1.84a3.5 3.5 0 0 0 3.98 4.75l-6.3 6.3a1 1 0 0 1-1.42 0l-1.17-1.18a1 1 0 0 1 0-1.41l6.3-6.3a3.5 3.5 0 0 0-4.75-3.99l2.02 2.02a1 1 0 0 1-1.41 1.42L4.56 1.43a.75.75 0 0 1 .16-1.2A4.5 4.5 0 0 1 11 5.83"></path></svg>` },
    { key: "bolt", label: "Bolt", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M9.482.568a.5.5 0 0 0-.93-.082L4.5 8h2.75L6.52 15.432a.5.5 0 0 0 .93.082L11.5 8H8.75z"></path></svg>` },
    { key: "download", label: "Download", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5a.5.5 0 0 1 .5.5v6.793l2.146-2.147a.5.5 0 1 1 .708.708l-3 3a.5.5 0 0 1-.708 0l-3-3a.5.5 0 1 1 .708-.708L7.5 8.793V2a.5.5 0 0 1 .5-.5"></path><path d="M2.5 11a.5.5 0 0 1 .5.5v1a.5.5 0 0 0 .5.5h9a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 1 1 0v1A1.5 1.5 0 0 1 12.5 14h-9A1.5 1.5 0 0 1 2 12.5v-1a.5.5 0 0 1 .5-.5"></path></svg>` },
    { key: "upload", label: "Upload", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 14.5a.5.5 0 0 1-.5-.5V7.207L5.354 9.354a.5.5 0 1 1-.708-.708l3-3a.5.5 0 0 1 .708 0l3 3a.5.5 0 1 1-.708.708L8.5 7.207V14a.5.5 0 0 1-.5.5"></path><path d="M2.5 5a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 .5.5v1a.5.5 0 0 0 1 0v-1A1.5 1.5 0 0 0 12.5 2h-9A1.5 1.5 0 0 0 2 3.5v1a.5.5 0 0 0 .5.5"></path></svg>` },
    { key: "desktop", label: "Desktop", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1.5 3A1.5 1.5 0 0 1 3 1.5h10A1.5 1.5 0 0 1 14.5 3v7A1.5 1.5 0 0 1 13 11.5H9.5V13H11a.5.5 0 0 1 0 1H5a.5.5 0 0 1 0-1h1.5v-1.5H3A1.5 1.5 0 0 1 1.5 10zm1 0v7a.5.5 0 0 0 .5.5h10a.5.5 0 0 0 .5-.5V3a.5.5 0 0 0-.5-.5H3a.5.5 0 0 0-.5.5"></path></svg>` },
    { key: "server", label: "Server", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1.5 2.5A1.5 1.5 0 0 1 3 1h10a1.5 1.5 0 0 1 1.5 1.5v2A1.5 1.5 0 0 1 13 6H3A1.5 1.5 0 0 1 1.5 4.5zm0 6A1.5 1.5 0 0 1 3 7h10a1.5 1.5 0 0 1 1.5 1.5v2A1.5 1.5 0 0 1 13 12H3a1.5 1.5 0 0 1-1.5-1.5zM4 4.5a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5m0 6a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5"></path></svg>` },
    { key: "lock", label: "Lock", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M4.5 6V4a3.5 3.5 0 1 1 7 0v2h.5A1.5 1.5 0 0 1 13.5 7.5v6A1.5 1.5 0 0 1 12 15H4A1.5 1.5 0 0 1 2.5 13.5v-6A1.5 1.5 0 0 1 4 6zm1 0h5V4a2.5 2.5 0 0 0-5 0z"></path></svg>` },
    { key: "search", label: "Search", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M11.742 10.344a6 6 0 1 0-1.398 1.398l2.978 2.978a1 1 0 0 0 1.414-1.414zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"></path></svg>` },
    { key: "folder", label: "Folder", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1.5 3A1.5 1.5 0 0 1 3 1.5h3.1a1.5 1.5 0 0 1 1.06.44l.9.9a.5.5 0 0 0 .35.15H13A1.5 1.5 0 0 1 14.5 4.5v7A1.5 1.5 0 0 1 13 13H3A1.5 1.5 0 0 1 1.5 11.5z"></path></svg>` },
    { key: "home", label: "Home", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="m8 3.293 5 5V13.5a.5.5 0 0 1-.5.5H9.5v-3h-3v3H3.5a.5.5 0 0 1-.5-.5V8.293z"></path><path d="M7.293 1.646a1 1 0 0 1 1.414 0l5.5 5.5a.5.5 0 0 1-.707.708L13 7.354V13.5a1.5 1.5 0 0 1-1.5 1.5h-7A1.5 1.5 0 0 1 3 13.5V7.354l-.5.5a.5.5 0 1 1-.707-.708z"></path></svg>` },
    { key: "globe", label: "Globe", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 15A7 7 0 1 0 8 1a7 7 0 0 0 0 14m4.93-6h-2.1a12.6 12.6 0 0 1-.52 3.01A6.02 6.02 0 0 0 12.93 9m-3.66 3.63c.2-.66.42-1.63.53-2.63H6.2c.11 1 .33 1.97.53 2.63a5.95 5.95 0 0 0 2.54 0M5.69 12.01A12.6 12.6 0 0 1 5.17 9h-2.1a6.02 6.02 0 0 0 2.62 3.01M3.07 8h2.1c.04-1.08.2-2.08.52-3.01A6.02 6.02 0 0 0 3.07 8m3.66-3.63A11.5 11.5 0 0 0 6.2 8h3.6c-.11-1-.33-1.97-.53-2.63a5.95 5.95 0 0 0-2.54 0m3.58.62c.32.93.48 1.93.52 3.01h2.1a6.02 6.02 0 0 0-2.62-3.01"></path></svg>` },
    { key: "shield", label: "Shield", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0c-.69 0-1.37.12-2.03.35L3.2 1.28A1.5 1.5 0 0 0 2 2.7v3.78c0 3.37 2.15 6.36 5.35 7.42a2 2 0 0 0 1.3 0C11.85 12.84 14 9.85 14 6.48V2.7a1.5 1.5 0 0 0-1.2-1.47L10.03.35A6.4 6.4 0 0 0 8 0"></path></svg>` },
    { key: "bell", label: "Bell", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1a4 4 0 0 0-4 4v2.086l-.707.707A1 1 0 0 0 4 9.5h8a1 1 0 0 0 .707-1.707L12 7.086V5a4 4 0 0 0-4-4m0 14a2 2 0 0 0 1.995-1.85L10 13H6a2 2 0 0 0 2 2"></path></svg>` },
    { key: "camera", label: "Camera", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M10.5 2a.5.5 0 0 1 .354.146L11.707 3H13.5A1.5 1.5 0 0 1 15 4.5v7A1.5 1.5 0 0 1 13.5 13h-11A1.5 1.5 0 0 1 1 11.5v-7A1.5 1.5 0 0 1 2.5 3h1.793l.853-.854A.5.5 0 0 1 5.5 2zM8 11a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5"></path></svg>` },
    { key: "trash", label: "Trash", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M5.5 5.5a.5.5 0 0 1 1 0v6a.5.5 0 0 1-1 0zm4 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0z"></path><path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1 0-2H5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1h2.5a1 1 0 0 1 1 1"></path></svg>` },
    { key: "edit", label: "Edit", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M12.854.146a.5.5 0 0 0-.707 0L10.5 1.793 14.207 5.5l1.647-1.646a.5.5 0 0 0 0-.708zM13.5 6.207 9.793 2.5 3 9.293V13h3.707z"></path></svg>` },
    { key: "moon", label: "Moon", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 0a.5.5 0 0 1 .46.694A6.5 6.5 0 1 0 15.306 9.54.5.5 0 0 1 16 10a7.5 7.5 0 1 1-10-10 .5.5 0 0 1 0 0"></path></svg>` },
    { key: "sun", label: "Sun", svg: `<svg class="btn-icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8m0-3a.5.5 0 0 1 .5.5V3a.5.5 0 0 1-1 0V1.5A.5.5 0 0 1 8 1m0 12a.5.5 0 0 1 .5.5V15a.5.5 0 0 1-1 0v-1.5A.5.5 0 0 1 8 13m7-5.5a.5.5 0 0 1-.5.5H13a.5.5 0 0 1 0-1h1.5a.5.5 0 0 1 .5.5M3 8a.5.5 0 0 1-.5.5H1a.5.5 0 0 1 0-1h1.5A.5.5 0 0 1 3 8m9.657-4.657a.5.5 0 0 1 0 .707L11.596 5.11a.5.5 0 1 1-.707-.707l1.06-1.06a.5.5 0 0 1 .708 0M5.11 10.889a.5.5 0 0 1 0 .707l-1.06 1.06a.5.5 0 0 1-.708-.707l1.061-1.06a.5.5 0 0 1 .707 0m7.546 1.767a.5.5 0 0 1-.707 0l-1.06-1.06a.5.5 0 1 1 .707-.707l1.06 1.06a.5.5 0 0 1 0 .707M5.11 5.11a.5.5 0 0 1-.707 0L3.343 4.05a.5.5 0 1 1 .707-.707l1.06 1.06a.5.5 0 0 1 0 .707"></path></svg>` }
  ];
  const ACTION_ICON_MAP = Object.fromEntries(ACTION_ICON_OPTIONS.filter(opt => opt.key).map(opt => [opt.key, opt]));
  let activeIconPicker = null;
  let iconSearchAbortController = null;
  let iconSearchDebounceTimer = null;

  function getActionIconDefinition(iconKey) {
    return ACTION_ICON_MAP[String(iconKey || "").trim()] || null;
  }

  function getRemoteIconUrl(iconKey) {
    const normalized = String(iconKey || "").trim();
    if (!normalized || !normalized.includes(":")) return "";
    return `https://api.iconify.design/${encodeURIComponent(normalized)}.svg`;
  }

  function getActionIconMarkup(iconKey) {
    const normalized = String(iconKey || "").trim();
    const localDef = getActionIconDefinition(normalized);
    if (localDef) return localDef.svg;
    if (normalized.includes(":")) {
      const iconUrl = getRemoteIconUrl(normalized);
      return `<span class="remote-icon" aria-hidden="true" style="-webkit-mask-image:url('${iconUrl}');mask-image:url('${iconUrl}');"></span>`;
    }
    return "";
  }

  function setButtonContentWithOptionalIcon(btn, iconKey, fallbackText) {
    const safeText = String(fallbackText || "").trim() || "Action";
    const iconMarkup = getActionIconMarkup(iconKey);
    btn.innerHTML = "";
    btn.title = safeText;
    btn.setAttribute("aria-label", safeText);

    if (iconMarkup) {
      btn.classList.add("btn-icon-only", "btn-action-icon");
      btn.insertAdjacentHTML("beforeend", iconMarkup);
      const sr = document.createElement("span");
      sr.className = "sr-only";
      sr.textContent = safeText;
      btn.appendChild(sr);
      return;
    }

    btn.classList.remove("btn-icon-only", "btn-action-icon");
    btn.textContent = safeText;
  }

  function setLinkContentWithOptionalIcon(linkEl, iconKey, fallbackText) {
    const safeText = String(fallbackText || "").trim() || "Open";
    const iconMarkup = getActionIconMarkup(iconKey);
    linkEl.innerHTML = "";
    linkEl.title = safeText;
    linkEl.setAttribute("aria-label", safeText);

    if (iconMarkup) {
      linkEl.classList.add("btn-icon-only", "btn-action-icon");
      linkEl.insertAdjacentHTML("beforeend", iconMarkup);
      const sr = document.createElement("span");
      sr.className = "sr-only";
      sr.textContent = safeText;
      linkEl.appendChild(sr);
      return;
    }

    linkEl.classList.remove("btn-icon-only", "btn-action-icon");
    linkEl.textContent = safeText;
  }

  function setIconValue(target, iconKey) {
    if (!target) return;
    const value = String(iconKey || "").trim();
    if ("value" in target) {
      target.value = value;
    } else {
      target.dataset.icon = value;
    }
  }

  function getIconValue(target) {
    if (!target) return "";
    if ("value" in target) return String(target.value || "").trim();
    return String(target.dataset.icon || "").trim();
  }

  function closeIconPicker() {
    activeIconPicker = null;
    if (iconSearchAbortController) {
      iconSearchAbortController.abort();
      iconSearchAbortController = null;
    }
    if (iconSearchDebounceTimer) {
      clearTimeout(iconSearchDebounceTimer);
      iconSearchDebounceTimer = null;
    }
    if (iconPickerOverlay) iconPickerOverlay.classList.add("hidden");
  }

  function setIconPickerStatus(text) {
    if (iconPickerStatusEl) iconPickerStatusEl.textContent = text || "";
  }

  function renderIconPickerGrid(items, selectedKey) {
    if (!iconPickerGrid) return;
    iconPickerGrid.innerHTML = "";
    items.forEach(opt => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "icon-option" + (opt.key === selectedKey ? " active" : "");
      if (!opt.key) {
        btn.classList.add("icon-option-none");
        btn.textContent = "No icon";
      } else {
        btn.innerHTML = `${getActionIconMarkup(opt.key)}<span>${opt.label}</span>`;
      }
      btn.addEventListener("click", () => {
        if (!activeIconPicker) return;
        setIconValue(activeIconPicker.input, opt.key);
        closeIconPicker();
      });
      iconPickerGrid.appendChild(btn);
    });
  }

  async function fetchIconSearchResults(query) {
    if (iconSearchAbortController) iconSearchAbortController.abort();
    iconSearchAbortController = new AbortController();

    const params = new URLSearchParams({
      query,
      limit: "120"
    });

    const res = await fetch(`https://api.iconify.design/search?${params.toString()}`, {
      signal: iconSearchAbortController.signal
    });
    if (!res.ok) throw new Error("search_failed");

    const data = await res.json();
    const icons = Array.isArray(data.icons) ? data.icons : [];
    return icons.map(name => ({ key: name, label: name.split(":").pop().replaceAll("-", " ") }));
  }

  async function runIconSearch(query) {
    const normalized = String(query || "").trim();
    if (!activeIconPicker) return;

    if (!normalized) {
      setIconPickerStatus("Popular icons");
      renderIconPickerGrid(ACTION_ICON_OPTIONS, getIconValue(activeIconPicker.input));
      return;
    }

    setIconPickerStatus("Searching...");
    try {
      const found = await fetchIconSearchResults(normalized);
      if (!activeIconPicker) return;
      if (!found.length) {
        setIconPickerStatus("No icons found.");
        renderIconPickerGrid([{ key: "", label: "No icon" }], getIconValue(activeIconPicker.input));
        return;
      }
      setIconPickerStatus(`Found ${found.length} icons`);
      renderIconPickerGrid([{ key: "", label: "No icon" }, ...found], getIconValue(activeIconPicker.input));
    } catch (err) {
      if (err && err.name === "AbortError") return;
      setIconPickerStatus("Search unavailable. Showing local icons.");
      renderIconPickerGrid(ACTION_ICON_OPTIONS, getIconValue(activeIconPicker.input));
    }
  }

  function openIconPicker(config) {
    activeIconPicker = config;
    if (iconPickerSearchInput) iconPickerSearchInput.value = "";
    setIconPickerStatus("Popular icons");
    renderIconPickerGrid(ACTION_ICON_OPTIONS, getIconValue(config.input));
    if (iconPickerOverlay) iconPickerOverlay.classList.remove("hidden");
    if (iconPickerSearchInput) iconPickerSearchInput.focus();
  }

  function showToast({ title, message, detail, type = "success", ttl = 5000 }) {
    if (!toastStack) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type === "error" ? "toast-error" : "toast-success"}`;

    const t = document.createElement("div");
    t.className = "toast-title";
    t.textContent = title || (type === "error" ? "Error" : "Success");

    const b = document.createElement("div");
    b.className = "toast-body";
    b.textContent = message || "";

    toast.appendChild(t);
    toast.appendChild(b);

    if (detail) {
      const d = document.createElement("div");
      d.className = "toast-detail";
      d.textContent = detail;
      toast.appendChild(d);
    }

    toastStack.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, ttl);
  }

  function formatActionError(resp) {
    if (!resp) return { message: "Unknown error", detail: "" };
    if (resp.result === "missing_sshpass") {
      return { message: "sshpass не установлен", detail: resp.detail || "" };
    }
    if (resp.result && resp.result !== "error") {
      return { message: `Result: ${resp.result}`, detail: resp.detail || "" };
    }
    return { message: "Action failed", detail: resp.detail || resp.result || "" };
  }

  function fmt(ts) {
    if (!ts) return "never";
    const d = new Date(ts);
    const pad = n => String(n).padStart(2, "0");
    return (
      d.getFullYear() + "-" +
      pad(d.getMonth() + 1) + "-" +
      pad(d.getDate()) + " " +
      pad(d.getHours()) + ":" +
      pad(d.getMinutes()) + ":" +
      pad(d.getSeconds())
    );
  }

  function updateViewAccessButtonsVisibility() {
    const show = !!privateAccessMode;
    if (viewLogoutBtn) viewLogoutBtn.classList.toggle("hidden", !show);
    if (viewLogoutHealthBtn) viewLogoutHealthBtn.classList.toggle("hidden", !show);
  }

  function syncSwitchLabelStates() {
    const accessPrivateOn = !!(accessPrivateEnabledInput && accessPrivateEnabledInput.checked);
    if (accessPublicLabel) accessPublicLabel.classList.toggle("active", !accessPrivateOn);
    if (accessPrivateLabel) accessPrivateLabel.classList.toggle("active", accessPrivateOn);

    const batteryOn = !!(batteryEnabledInput && batteryEnabledInput.checked);
    if (batteryDisabledLabel) batteryDisabledLabel.classList.toggle("active", !batteryOn);
    if (batteryEnabledLabel) batteryEnabledLabel.classList.toggle("active", batteryOn);
  }

  function showAccessOverlay(message = "") {
    viewAccessGranted = false;
    if (accessStatusEl) {
      accessStatusEl.textContent = message;
      accessStatusEl.classList.toggle("error", !!message);
      accessStatusEl.classList.remove("success");
    }
    if (accessPassInput) accessPassInput.value = "";
    if (accessOverlay) accessOverlay.classList.remove("hidden");
    if (accessPassInput) accessPassInput.focus();
  }

  function hideAccessOverlay() {
    if (accessOverlay) accessOverlay.classList.add("hidden");
    if (accessStatusEl) {
      accessStatusEl.textContent = "";
      accessStatusEl.classList.remove("error", "success");
    }
  }

  async function loadAccessStatus() {
    const res = await fetch(API_BASE + "/access/status", { credentials: "include" });
    const data = await res.json().catch(() => ({}));
    privateAccessMode = !!data.privateMode;
    viewAccessGranted = !!data.authorized;
    updateViewAccessButtonsVisibility();
    return data;
  }

  async function handleUnauthorizedResponse() {
    try {
      const status = await loadAccessStatus();
      if (status.privateMode && !status.authorized) {
        showAccessOverlay("Session expired. Please sign in again.");
        return;
      }
    } catch {
      // ignore and fallback to admin logout UI
    }
    forceLogoutUI();
  }

  async function apiGET(path) {
    const res = await fetch(API_BASE + path, {
      credentials: "include"
    });
    if (res.status === 401) {
      await handleUnauthorizedResponse();
      return {};
    }
    return res.json().catch(() => ({}));
  }

  async function apiJSON(method, path, bodyObj) {
    const res = await fetch(API_BASE + path, {
      method,
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyObj)
    });
    if (res.status === 401) {
      await handleUnauthorizedResponse();
      return {};
    }
    return res.json().catch(() => ({}));
  }

  async function apiDELETE(path) {
    const res = await fetch(API_BASE + path, {
      method: "DELETE",
      credentials: "include"
    });
    if (res.status === 401) {
      await handleUnauthorizedResponse();
      return {};
    }
    return res.json().catch(() => ({}));
  }

  async function apiPOSTNoBody(path) {
    const res = await fetch(API_BASE + path, {
      method: "POST",
      credentials: "include"
    });
    if (res.status === 401) {
      await handleUnauthorizedResponse();
      return {};
    }
    return res.json().catch(() => ({}));
  }

  async function apiRaw(method, path, body, contentType = "application/json") {
    const headers = {};
    if (contentType) headers["Content-Type"] = contentType;
    const res = await fetch(API_BASE + path, {
      method,
      credentials: "include",
      headers,
      body
    });
    if (res.status === 401) {
      await handleUnauthorizedResponse();
    }
    return res;
  }

  // helper: ask for password only when needed for protected actions
  async function ensureAdminThen(actionFn, { force = false } = {}) {
    if (editMode && !force) {
      await actionFn();
      return;
    }
    pendingAction = actionFn;
    adminPassInput.value = "";
    if (adminStatusEl) {
      adminStatusEl.textContent = "";
      adminStatusEl.classList.remove("error", "success");
    }
    adminOverlay.classList.remove("hidden");
    adminPassInput.focus();
  }

  // ==============================
  // TERMINAL (xterm.js)
  // ==============================
  let terminalSocket = null;
  let terminalOpening = false;
  let terminalFitAddon = null;
  let terminalNeedsAuth = false;
  const terminalEncoder = new TextEncoder();
  const terminalDecoder = new TextDecoder();

  function ensureTerminalInstance() {
    if (window.termInstance || !terminalShellEl) return;
    if (!window.Terminal) {
      if (terminalStatusEl) terminalStatusEl.textContent = "Terminal library unavailable";
      return;
    }

    const term = new window.Terminal({
      cursorBlink: true,
      fontSize: 13,
      scrollback: 2000,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
      theme: buildTerminalTheme()
    });

    if (window.FitAddon) {
      terminalFitAddon = new window.FitAddon.FitAddon();
      term.loadAddon(terminalFitAddon);
    }

    term.open(terminalShellEl);
    if (terminalFitAddon) terminalFitAddon.fit();
    window.termInstance = term;

    term.onData(data => {
      if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
        terminalSocket.send(terminalEncoder.encode(data));
      }
    });
  }

  function openTerminalModal(forceAuth = false) {
    if (terminalOpening) return;
    if (!terminalOverlay) return;

    if ((terminalNeedsAuth || !editMode) && !forceAuth) {
      ensureAdminThen(() => {
        terminalNeedsAuth = false;
        openTerminalModal(true);
      }, { force: true });
      return;
    }

    if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
      terminalOverlay.classList.remove("hidden");
      if (terminalFitAddon) terminalFitAddon.fit();
      if (window.termInstance) {
        window.termInstance.focus();
        window.termInstance.scrollToBottom();
      }
      return;
    }

    terminalOpening = true;
    if (terminalStatusEl) terminalStatusEl.textContent = "Checking terminal...";

    updateTerminalCapabilityStatus()
      .then(status => {
        if (status && status.unauthorized) {
          terminalOpening = false;
          terminalNeedsAuth = true;
          ensureAdminThen(() => {
            terminalNeedsAuth = false;
            openTerminalModal(true);
          }, { force: true });
          return;
        }

        if (status && !status.ok) {
          terminalOpening = false;
          return;
        }

        if (terminalStatusEl) terminalStatusEl.textContent = "Connecting...";

        const wsUrl = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/api/terminal";
        const ws = new WebSocket(wsUrl);
        ws.binaryType = "arraybuffer";

        let ready = false;

        ws.onmessage = evt => {
          if (typeof evt.data === "string") {
            try {
              const msg = JSON.parse(evt.data);
              if (msg && msg.type === "ready") {
                ready = true;
                terminalSocket = ws;
                ensureTerminalInstance();
                if (forceAuth && window.termInstance) window.termInstance.reset();
                terminalOverlay.classList.remove("hidden");
                if (terminalStatusEl) terminalStatusEl.textContent = "Connected";
                if (terminalFitAddon) terminalFitAddon.fit();
                if (window.termInstance) {
                  window.termInstance.focus();
                  window.termInstance.scrollToBottom();
                }
                terminalOpening = false;
                return;
              }
              if (msg && msg.type === "closed") {
                if (terminalStatusEl) terminalStatusEl.textContent = "Session closed";
                terminalNeedsAuth = true;
                if (terminalOverlay) terminalOverlay.classList.add("hidden");
                return;
              }
            } catch {
              // ignore
            }
            return;
          }

          if (window.termInstance) {
            window.termInstance.write(terminalDecoder.decode(evt.data));
          }
        };

        ws.onclose = evt => {
          if (!ready && evt.code === 4401 && !forceAuth) {
            terminalOpening = false;
            terminalNeedsAuth = true;
            ensureAdminThen(() => {
              terminalNeedsAuth = false;
              openTerminalModal(true);
            }, { force: true });
            return;
          }

          if (!ready && terminalStatusEl) {
            terminalStatusEl.textContent = "Terminal unavailable";
            if (evt.code === 1011) {
              updateTerminalCapabilityStatus();
            }
          }
          if (ready && terminalStatusEl) {
            terminalStatusEl.textContent = "Disconnected";
          }

          if (terminalSocket === ws) terminalSocket = null;
          terminalOpening = false;
        };

        ws.onerror = () => {
          if (!ready && terminalStatusEl) terminalStatusEl.textContent = "Terminal error";
        };
      })
      .catch(() => {
        terminalOpening = false;
        if (terminalStatusEl) terminalStatusEl.textContent = "Terminal unavailable";
      });
  }

  async function updateTerminalCapabilityStatus() {
    if (!terminalStatusEl) return;
    const res = await fetch(API_BASE + "/terminal/status", {
      credentials: "include"
    });
    if (res.status === 401) {
      return { ok: false, unauthorized: true };
    }
    const status = await res.json().catch(() => ({}));
    if (!status || status.ok) return status;
    if (status.missing === "script" || status.missing === "shell") {
      terminalStatusEl.textContent = status.hint || "Terminal prerequisites are missing";
    }
    return status;
  }

  // ==============================
  // LOGIN / LOGOUT FLOW (one-shot actions)
  // ==============================
  async function logoutViewAccess() {
    await fetch(API_BASE + "/access/logout", {
      method: "POST",
      credentials: "include"
    });
  }

  async function handleViewLogoutClick() {
    if (!privateAccessMode) return;
    const ok = window.confirm("Log out from Wadboard view access?");
    if (!ok) return;
    await logoutViewAccess();
    showAccessOverlay("");
  }

  if (viewLogoutBtn) {
    viewLogoutBtn.addEventListener("click", handleViewLogoutClick);
  }
  if (viewLogoutHealthBtn) {
    viewLogoutHealthBtn.addEventListener("click", handleViewLogoutClick);
  }

  if (accessForm) {
    accessForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const pw = accessPassInput ? accessPassInput.value : "";
      if (!pw) return;

      if (accessStatusEl) {
        accessStatusEl.textContent = "";
        accessStatusEl.classList.remove("error", "success");
      }

      const res = await fetch(API_BASE + "/access/login", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pw })
      });

      if (res.status === 200) {
        viewAccessGranted = true;
        hideAccessOverlay();
        if (!appStarted) {
          await startApp();
        }
        return;
      }

      const payload = await res.json().catch(() => ({}));
      if (accessStatusEl) {
        if (res.status === 429) {
          const sec = Number(payload && payload.retryAfterSec);
          accessStatusEl.textContent = Number.isFinite(sec) && sec > 0
            ? `Too many attempts. Try again in ${sec}s.`
            : "Too many attempts. Try again later.";
        } else {
          accessStatusEl.textContent = "Wrong admin password.";
        }
        accessStatusEl.classList.add("error");
      }
      if (accessPassInput) {
        accessPassInput.value = "";
        accessPassInput.focus();
      }
    });
  }

  if (adminToggleBtn) {
    adminToggleBtn.addEventListener("click", () => openSettingsModal());
  }
  if (adminToggleHealthBtn) {
    adminToggleHealthBtn.addEventListener("click", () => openSettingsModal());
  }

  adminCloseBtn.addEventListener("click", () => {
    pendingAction = null;
    adminOverlay.classList.add("hidden");
  });

  adminForm.addEventListener("submit", async e => {
    e.preventDefault();
    const pw = adminPassInput.value;

    if (adminStatusEl) {
      adminStatusEl.textContent = "";
      adminStatusEl.classList.remove("error", "success");
    }

    const res = await fetch(API_BASE + "/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw })
    });

    if (res.status === 200) {
      const isQuickAction = !!pendingAction;

      // For one-shot WOL/SSH/host actions: execute and stay in normal mode
      if (isQuickAction && pendingAction) {
        adminOverlay.classList.add("hidden");
        const fn = pendingAction;
        pendingAction = null;

        await loadStateFromServer();
        await fn();
      } else {
        // Fallback: if called without pendingAction, do not enable editMode here
        adminOverlay.classList.add("hidden");
      }
    } else {
      const payload = await res.json().catch(() => ({}));
      const err = payload && payload.error ? payload.error : "bad_password";
      if (adminStatusEl) {
        adminStatusEl.textContent =
          err === "password_too_short"
            ? "Password too short (min 6 characters)."
            : "Wrong admin password.";
        adminStatusEl.classList.add("error");
      }
      adminPassInput.value = "";
      adminPassInput.focus();
    }
  });

  async function logoutRequest() {
    await fetch(API_BASE + "/logout", {
      method: "POST",
      credentials: "include"
    });
  }


function syncSettingsUI() {
  const adminOnlyBox = document.getElementById("settings-admin-only");

  if (editMode) {
    settingsSessionText.textContent =
      "Edit mode is enabled for this browser session.";
    settingsLoginForm.classList.add("hidden");
    settingsLogoutRow.classList.remove("hidden");
    adminOnlyBox.classList.remove("hidden");
  } else {
    settingsSessionText.textContent =
      "Enter admin password to enable editing and configure additional features.";
    settingsLoginForm.classList.remove("hidden");
    settingsLogoutRow.classList.add("hidden");
    adminOnlyBox.classList.add("hidden");
  }
}



  function forceLogoutUI() {
    editMode = false;
    pendingAction = null;
    openBtn.classList.add("hidden");
    render();
  }

  // ==============================
  // SETTINGS MODAL (edit mode + battery alerts)
  // ==============================
 
async function changeAdminPassword(oldPw, newPw) {
  const res = await apiJSON("PUT", "/admin/password", {
    oldPassword: oldPw,
    newPassword: newPw
  });

  if (res && res.ok) {
    showToast({ title: "Admin Password", message: "Password changed", type: "success" });
  } else {
    showToast({ title: "Admin Password", message: "Password change failed", type: "error" });
  }
}



 async function loadAccessModeIntoForm() {
    if (!accessPrivateEnabledInput) return;
    const status = await loadAccessStatus();
    isSyncingAccessSwitch = true;
    accessPrivateEnabledInput.checked = !!status.privateMode;
    isSyncingAccessSwitch = false;
    syncSwitchLabelStates();
    if (accessSaveStatus) accessSaveStatus.textContent = "";
  }

 async function loadBatteryConfigIntoForm() {
    if (!batteryEnabledInput) return;
    const cfg = await apiGET("/battery-alerts");
    if (!cfg) return;

    batteryEnabledInput.checked = !!cfg.enabled;
    if (Array.isArray(cfg.levels) && cfg.levels.length) {
      batteryLevelsInput.value = cfg.levels.join(",");
    } else {
      batteryLevelsInput.value = "30,15,5";
    }
    batteryBotTokenInput.value = cfg.telegramBotToken || "";
    batteryChatIdInput.value = cfg.telegramChatId || "";
    syncSwitchLabelStates();
    batterySaveStatus.textContent = "";
  }

  function formatSessionTime(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return "—";
    return new Date(n).toLocaleString();
  }

  function setViewSessionsStatus(text) {
    if (viewSessionsStatusEl) viewSessionsStatusEl.textContent = text || "";
  }

  function clearViewSessionsList() {
    if (!viewSessionsListEl) return;
    viewSessionsListEl.innerHTML = "";
  }

  function renderViewSessionsList(items) {
    if (!viewSessionsListEl) return;
    viewSessionsListEl.innerHTML = "";

    if (!Array.isArray(items) || items.length === 0) {
      const empty = document.createElement("div");
      empty.style.fontSize = ".76rem";
      empty.style.color = "var(--text-dim)";
      empty.textContent = "No active view sessions.";
      viewSessionsListEl.appendChild(empty);
      return;
    }

    for (const s of items) {
      const row = document.createElement("div");
      row.className = "session-item";

      const left = document.createElement("div");
      left.style.minWidth = "0";

      const title = document.createElement("div");
      title.style.fontWeight = "700";
      title.style.fontSize = ".82rem";
      title.style.color = "var(--text-main)";
      title.textContent = `${s.browser || "Unknown"} on ${s.os || "Unknown"}${s.current ? " (Current)" : ""}`;

      const meta = document.createElement("div");
      meta.className = "session-meta";

      const ip = document.createElement("span");
      ip.textContent = `IP: ${s.ip || "unknown"}`;
      const created = document.createElement("span");
      created.textContent = `Created: ${formatSessionTime(s.createdAt)}`;
      const lastSeen = document.createElement("span");
      lastSeen.textContent = `Last seen: ${formatSessionTime(s.lastSeenAt)}`;
      const lang = document.createElement("span");
      lang.textContent = `Lang: ${s.language || "—"}`;
      const token = document.createElement("span");
      token.textContent = `Session: ${s.tokenPreview || "—"}`;

      meta.appendChild(ip);
      meta.appendChild(created);
      meta.appendChild(lastSeen);
      meta.appendChild(lang);
      meta.appendChild(token);

      left.appendChild(title);
      left.appendChild(meta);

      const revokeBtn = document.createElement("button");
      revokeBtn.className = "btn btn-danger";
      revokeBtn.type = "button";
      revokeBtn.textContent = "Revoke";
      revokeBtn.addEventListener("click", async () => {
        const ok = window.confirm(s.current
          ? "Revoke current session and lock this browser out of view mode?"
          : "Revoke this view session?");
        if (!ok) return;
        const resp = await apiDELETE("/access/sessions/" + encodeURIComponent(s.token));
        if (resp && resp.ok) {
          if (resp.revokedCurrent) {
            closeSettingsModal();
            showAccessOverlay("Session revoked. Please sign in again.");
            return;
          }
          setViewSessionsStatus("Session revoked.");
          await loadViewSessionsIntoForm();
        } else {
          setViewSessionsStatus("Failed to revoke session.");
        }
      });

      row.appendChild(left);
      row.appendChild(revokeBtn);
      viewSessionsListEl.appendChild(row);
    }
  }

  async function loadViewSessionsIntoForm() {
    if (!viewSessionsListEl) return;
    setViewSessionsStatus("Loading...");
    const data = await apiGET("/access/sessions");
    if (!data || !data.ok) {
      clearViewSessionsList();
      setViewSessionsStatus("Unable to load sessions.");
      return;
    }
    renderViewSessionsList(data.sessions || []);
    setViewSessionsStatus("");
  }

  function openSettingsModal() {
    if (!settingsOverlay) return;
    settingsOverlay.classList.remove("hidden");
    const adminOnlyBox = document.getElementById("settings-admin-only");

    if (editMode) {
      settingsSessionText.textContent = "Edit mode is enabled for this browser session.";
      settingsLoginForm.classList.add("hidden");
      settingsLogoutRow.classList.remove("hidden");
      adminOnlyBox.classList.remove("hidden");
      if (configImportStatus) configImportStatus.textContent = "";
      loadBrandTextIntoForm();
      loadAccessModeIntoForm();
      loadBatteryConfigIntoForm();
      loadViewSessionsIntoForm();
    } else {
      settingsSessionText.textContent = "Enter admin password to enable editing and configure additional features.";
      settingsLoginForm.classList.remove("hidden");
      settingsLogoutRow.classList.add("hidden");
      settingsPassInput.value = "";
      settingsPassInput.focus();
      if (settingsLoginStatusEl) {
        settingsLoginStatusEl.textContent = "";
        settingsLoginStatusEl.classList.remove("error", "success");
      }
      adminOnlyBox.classList.add("hidden");
    }
  }

  function closeSettingsModal() {
    if (!settingsOverlay) return;
    settingsOverlay.classList.add("hidden");
  }

  async function exportConfig() {
    if (configImportStatus) configImportStatus.textContent = "Preparing export...";
    const res = await fetch(API_BASE + "/config/export", {
      credentials: "include"
    });
    if (res.status === 401) {
      if (configImportStatus) configImportStatus.textContent = "Admin session required.";
      showToast({ title: "Config Export", message: "Admin session required", type: "error" });
      await handleUnauthorizedResponse();
      return;
    }
    if (!res.ok) {
      if (configImportStatus) configImportStatus.textContent = "Export failed.";
      showToast({ title: "Config Export", message: "Export failed", type: "error" });
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const disposition = res.headers.get("content-disposition") || "";
    const match = disposition.match(/filename=\"?([^"]+)\"?/i);
    a.href = url;
    a.download = match ? match[1] : "wadboard-config.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    if (configImportStatus) configImportStatus.textContent = "Config exported.";
    showToast({ title: "Config Export", message: "Downloaded successfully", type: "success" });
  }

  async function importConfigFile(file) {
    if (!file) return;
    if (configImportStatus) configImportStatus.textContent = "Validating JSON...";

    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      if (configImportStatus) configImportStatus.textContent = "Invalid JSON file.";
      showToast({ title: "Config Import", message: "Invalid JSON file", type: "error" });
      return;
    }

    if (configImportStatus) configImportStatus.textContent = "Importing...";
    const res = await apiRaw("POST", "/config/import", JSON.stringify(parsed));
    const payload = await res.json().catch(() => ({}));
    if (res.status === 401) {
      if (configImportStatus) configImportStatus.textContent = "Admin session required.";
      showToast({ title: "Config Import", message: "Admin session required", type: "error" });
      return;
    }
    if (!res.ok || !payload || !payload.ok) {
      const message = payload && payload.message ? payload.message : "Import failed.";
      if (configImportStatus) configImportStatus.textContent = message;
      showToast({ title: "Config Import", message, type: "error" });
      return;
    }

    state = {
      services: payload.state?.services || [],
      links: payload.state?.links || [],
      wol: payload.state?.wol || [],
      hostActions: payload.state?.hostActions || []
    };
    render();
    await refreshBrandTextFromServer();
    await loadAccessModeIntoForm();
    await loadBatteryConfigIntoForm();
    await loadViewSessionsIntoForm();

    const detail = payload.backupFile ? `Backup: ${payload.backupFile}` : "";
    if (configImportStatus) {
      configImportStatus.textContent = detail
        ? `Imported successfully. ${detail}`
        : "Imported successfully.";
    }
    showToast({
      title: "Config Import",
      message: "Imported successfully",
      detail,
      type: "success"
    });
  }

  function openLogsModal() {
    if (!logsOverlay) return;
    logsOverlay.classList.remove("hidden");
    loadLogsIntoViewer();
  }

  function closeLogsModal() {
    if (!logsOverlay) return;
    logsOverlay.classList.add("hidden");
  }

  async function loadLogsIntoViewer() {
    if (!logsViewerEl) return;
    if (logsStatusEl) logsStatusEl.textContent = "Loading...";
    const data = await apiGET("/logs?limit=250");
    if (!data || !data.ok) {
      logsViewerEl.textContent = "Unable to load logs.";
      if (logsStatusEl) logsStatusEl.textContent = "Load failed.";
      return;
    }
    logsViewerEl.textContent = (data.lines || []).join("\n") || "No log entries yet.";
    logsViewerEl.scrollTop = logsViewerEl.scrollHeight;
    if (logsStatusEl) logsStatusEl.textContent = `Showing last ${(data.lines || []).length} lines.`;
  }

  settingsCloseBtn.addEventListener("click", closeSettingsModal);

  settingsLoginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = settingsPassInput.value;
    if (!pw) return;

    if (settingsLoginStatusEl) {
      settingsLoginStatusEl.textContent = "";
      settingsLoginStatusEl.classList.remove("error", "success");
    }

    const res = await fetch(API_BASE + "/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw })
    });

    if (res.status === 200) {
      editMode = true;
      openBtn.classList.remove("hidden");

      settingsSessionText.textContent = "Edit mode is enabled for this browser session.";
      settingsLoginForm.classList.add("hidden");
      settingsLogoutRow.classList.remove("hidden");

      syncSettingsUI();

      await loadStateFromServer();
      await loadAccessModeIntoForm();
      // updateBatteryFormDisabled();
      await loadBatteryConfigIntoForm();
      await loadViewSessionsIntoForm();
    } else {
      const payload = await res.json().catch(() => ({}));
      const err = payload && payload.error ? payload.error : "bad_password";
      if (settingsLoginStatusEl) {
        settingsLoginStatusEl.textContent =
          err === "password_too_short"
            ? "Password too short (min 6 characters)."
            : "Wrong admin password.";
        settingsLoginStatusEl.classList.add("error");
      }
      settingsPassInput.value = "";
      settingsPassInput.focus();
    }
  });

  settingsLogoutBtn.addEventListener("click", async () => {
     await logoutRequest();
     editMode = false;
     terminalNeedsAuth = true;
     if (terminalOverlay) terminalOverlay.classList.add("hidden");
     if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
       terminalSocket.close(1000, "logout");
     }
     forceLogoutUI();
     syncSettingsUI();
     closeSettingsModal();
  });

if (accessPrivateEnabledInput) {
  accessPrivateEnabledInput.addEventListener("change", async () => {
    syncSwitchLabelStates();
    if (isSyncingAccessSwitch) return;
    if (!editMode) {
      isSyncingAccessSwitch = true;
      accessPrivateEnabledInput.checked = privateAccessMode;
      isSyncingAccessSwitch = false;
      syncSwitchLabelStates();
      return;
    }

    const privateMode = !!accessPrivateEnabledInput.checked;
    if (accessSaveStatus) accessSaveStatus.textContent = "Saving...";
    try {
      const resp = await apiJSON("PUT", "/access/mode", { privateMode });
      if (resp && resp.ok) {
        privateAccessMode = !!resp.privateMode;
        viewAccessGranted = !!resp.authorized;
        updateViewAccessButtonsVisibility();
        if (accessSaveStatus) accessSaveStatus.textContent = "Saved";
      } else {
        throw new Error("save_failed");
      }
    } catch {
      isSyncingAccessSwitch = true;
      accessPrivateEnabledInput.checked = privateAccessMode;
      isSyncingAccessSwitch = false;
      syncSwitchLabelStates();
      if (accessSaveStatus) accessSaveStatus.textContent = "Save failed";
    }
  });
}

if (batteryEnabledInput) {
  batteryEnabledInput.addEventListener("change", () => {
    syncSwitchLabelStates();
  });
}

if (viewSessionsRefreshBtn) {
  viewSessionsRefreshBtn.addEventListener("click", async () => {
    await loadViewSessionsIntoForm();
  });
}

if (viewSessionsRevokeOthersBtn) {
  viewSessionsRevokeOthersBtn.addEventListener("click", async () => {
    const ok = window.confirm("Revoke all other view sessions?");
    if (!ok) return;
    setViewSessionsStatus("Revoking...");
    const resp = await apiPOSTNoBody("/access/sessions/revoke-others");
    if (resp && resp.ok) {
      setViewSessionsStatus("Other sessions revoked.");
      await loadViewSessionsIntoForm();
    } else {
      setViewSessionsStatus("Failed to revoke other sessions.");
    }
  });
}

if (configExportBtn) {
  configExportBtn.addEventListener("click", async () => {
    await exportConfig();
  });
}

if (configImportBtn && configImportInput) {
  configImportBtn.addEventListener("click", () => {
    configImportInput.value = "";
    configImportInput.click();
  });

  configImportInput.addEventListener("change", async () => {
    const file = configImportInput.files && configImportInput.files[0];
    await importConfigFile(file);
  });
}

if (viewLogsBtn) {
  viewLogsBtn.addEventListener("click", () => {
    openLogsModal();
  });
}

if (logsCloseBtn) {
  logsCloseBtn.addEventListener("click", closeLogsModal);
}

if (logsRefreshBtn) {
  logsRefreshBtn.addEventListener("click", async () => {
    await loadLogsIntoViewer();
  });
}

batterySaveBtn.addEventListener("click", async () => {
  if (!editMode) return;

    const enabled = !!batteryEnabledInput.checked;
    const rawLevels = batteryLevelsInput.value || "";
    const levels = rawLevels
      .split(/[,\s]+/)
      .map(x => parseInt(x, 10))
      .filter(n => Number.isFinite(n) && n > 0 && n <= 100);

    const body = {
      enabled,
      levels: levels.length ? levels : undefined,
      telegramBotToken: batteryBotTokenInput.value.trim(),
      telegramChatId: batteryChatIdInput.value.trim()
    };

    batterySaveStatus.textContent = "Saving...";
    const resp = await apiJSON("PUT", "/battery-alerts", body);
    if (resp && resp.ok) {
      batterySaveStatus.textContent = "Saved.";
    } else {
      batterySaveStatus.textContent = "Error saving settings.";
    }
  });

  // ==============================
  // SERVER SYNC
  // ==============================
  async function loadStateFromServer() {
    const data = await apiGET("/state");
    state = {
      services: data.services || [],
      links: data.links || [],
      wol: data.wol || [],
      hostActions: data.hostActions || []
    };
    render();
  }

  async function persistOrderServices() {
    const order = state.services.map(s => s.id);
    await apiJSON("PUT", "/reorder/services", { order });
  }

  async function persistOrderLinks() {
    const order = state.links.map(l => l.id);
    await apiJSON("PUT", "/reorder/links", { order });
  }

  async function persistOrderWOL() {
    const order = state.wol.map(w => w.id);
    await apiJSON("PUT", "/reorder/wol", { order });
  }

  // ==============================
  // MODAL / FORMS
  // ==============================
  function updateSvcCheckLabel() {
    if (svcMethodEl.value === "ping") {
      svcCheckLabelEl.textContent = "Host/IP to ping";
      svcCheckInputEl.placeholder = "192.168.100.10";
    } else {
      svcCheckLabelEl.textContent = "Check URL (health probe)";
      svcCheckInputEl.placeholder = "http://service.local";
    }
  }
  svcMethodEl.addEventListener("change", updateSvcCheckLabel);

  function updateWolCheckLabel() {
    if (wolCheckMethodEl && wolCheckMethodEl.value === "ping") {
      wolCheckLabelEl.textContent = "Host/IP to ping";
      wolCheckInputEl.placeholder = "192.168.100.10";
    } else if (wolCheckLabelEl && wolCheckInputEl) {
      wolCheckLabelEl.textContent = "Check URL (health probe)";
      wolCheckInputEl.placeholder = "http://host.local/status";
    }
  }
  if (wolCheckMethodEl) {
    wolCheckMethodEl.addEventListener("change", updateWolCheckLabel);
  }

  function resetServiceForm() {
    document.getElementById("svc-name").value     = "";
    document.getElementById("svc-open").value     = "";
    svcMethodEl.value                             = "http";
    document.getElementById("svc-check").value    = "";
    document.getElementById("svc-notes").value    = "";
    updateSvcCheckLabel();
  }

  function resetLinkForm() {
    document.getElementById("lnk-title").value = "";
    document.getElementById("lnk-url").value   = "";
    document.getElementById("lnk-icon").value  = "";
    document.getElementById("lnk-notes").value = "";
  }

  function clearWolSshForm() {
    wolSshList.innerHTML = "";
    renumberWolSshRows();
  }

  function resetWolForm() {
    const typeEl = document.getElementById("wol-type");
    if (typeEl) typeEl.value = "basic";
    document.getElementById("wol-name").value   = "";
    document.getElementById("wol-host").value   = "";
    document.getElementById("wol-user").value   = "";
    document.getElementById("wol-pass").value   = "";
    document.getElementById("wol-script").value = "";
    document.getElementById("wol-notes").value  = "";
    if (wolCheckMethodEl) wolCheckMethodEl.value = "http";
    if (wolCheckInputEl) wolCheckInputEl.value = "";
    document.getElementById("wol-mac").value       = "";
    document.getElementById("wol-broadcast").value = "";
    document.getElementById("wol-port").value      = "";
    document.getElementById("wol-secureon").value  = "";
    document.getElementById("wol-esp-host").value  = "";
    const tokEl = document.getElementById("wol-esp-token");
    if (tokEl) tokEl.value = "";
    if (typeof updateWolTypeUI === "function") updateWolTypeUI();
    if (typeof updateWolCheckLabel === "function") updateWolCheckLabel();
    clearWolSshForm();
  }

  function resetHostForm() {
    hostLabelInput.value   = "";
    if (hostIconInput) hostIconInput.value = "";
    hostCommandInput.value = "";
    hostNotesInput.value   = "";
  }

  function updateFormTitles() {
    if (mode.type === "service") {
      if (mode.action === "create") {
        svcTitleEl.textContent  = "Add Service";
        svcSubmitEl.textContent = "Create Service";
      } else {
        svcTitleEl.textContent  = "Edit Service";
        svcSubmitEl.textContent = "Save Changes";
      }
    } else if (mode.type === "link") {
      if (mode.action === "create") {
        lnkTitleEl.textContent  = "Add Link";
        lnkSubmitEl.textContent = "Create Link";
      } else {
        lnkTitleEl.textContent  = "Edit Link";
        lnkSubmitEl.textContent = "Save Changes";
      }
    } else if (mode.type === "wol") {
      if (mode.action === "create") {
        wolTitleEl.textContent  = "Add WOL";
        wolSubmitEl.textContent = "Create WOL";
      } else {
        wolTitleEl.textContent  = "Edit WOL";
        wolSubmitEl.textContent = "Save Changes";
      }
    } else {
      if (mode.action === "create") {
        hostTitleEl.textContent  = "Add Device Command";
        hostSubmitEl.textContent = "Create Command";
      } else {
        hostTitleEl.textContent  = "Edit Device Command";
        hostSubmitEl.textContent = "Save Changes";
      }
    }
  }

  function showOnlyForm(which) {
    formSvc.classList.add("hidden");
    formLnk.classList.add("hidden");
    formWol.classList.add("hidden");
    formHost.classList.add("hidden");

    if (which === "service") formSvc.classList.remove("hidden");
    if (which === "link")    formLnk.classList.remove("hidden");
    if (which === "wol")     formWol.classList.remove("hidden");
    if (which === "host")    formHost.classList.remove("hidden");
  }

  function createWolSshRow(action) {
    const row = document.createElement("div");
    row.className = "ssh-row";
    const title = document.createElement("div");
    title.className = "ssh-row-title";
    title.textContent = "SSH Action";

    // SSH action inputs (label/user/host/pass/command)
    const labelInput = document.createElement("input");
    labelInput.className = "input ssh-input";
    labelInput.placeholder = "Button label (e.g. Shutdown PC)";
    labelInput.value = action.label || "";
    labelInput.dataset.field = "label";

    const iconInput = document.createElement("input");
    iconInput.type = "hidden";
    iconInput.dataset.field = "icon";
    iconInput.value = action.icon || "";

    const iconTrigger = document.createElement("button");
    iconTrigger.type = "button";
    iconTrigger.className = "btn icon-picker-trigger";
    iconTrigger.textContent = "Choose Icon";

    const userInput = document.createElement("input");
    userInput.className = "input ssh-input";
    userInput.placeholder = "SSH user";
    userInput.value = action.user || "";
    userInput.dataset.field = "user";

    const hostInput = document.createElement("input");
    hostInput.className = "input ssh-input";
    hostInput.placeholder = "SSH host (default: MikroTik Host/IP)";
    hostInput.value = action.host || wolHostInput.value.trim();
    hostInput.dataset.field = "host";

    const passInput = document.createElement("input");
    passInput.className = "input ssh-input";
    passInput.type = "password";
    passInput.placeholder = "SSH password (optional)";
    passInput.value = action.pass || "";
    passInput.dataset.field = "pass";

    const passNote = document.createElement("div");
    passNote.className = "ssh-note";
    passNote.textContent = "Note: Password-based SSH requires sshpass to be installed on the device where Wadboard is running";

    function syncPassNote() {
      const hasPass = !!String(passInput.value || "").trim();
      passNote.style.display = hasPass ? "block" : "none";
    }
    passInput.addEventListener("input", syncPassNote);
    syncPassNote();

    const cmdInput = document.createElement("input");
    cmdInput.className = "input ssh-input";
    cmdInput.placeholder = "SSH command (e.g. sudo systemctl poweroff)";
    cmdInput.value = action.command || "";
    cmdInput.dataset.field = "command";

    iconTrigger.addEventListener("click", () => {
      openIconPicker({
        input: iconInput
      });
    });

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn btn-danger";
    removeBtn.textContent = "Remove";
    removeBtn.onclick = () => {
      row.remove();
      renumberWolSshRows();
    };

    row.appendChild(title);
    row.appendChild(labelInput);
    row.appendChild(iconInput);
    row.appendChild(iconTrigger);
    row.appendChild(userInput);
    row.appendChild(hostInput);
    row.appendChild(passInput);
    row.appendChild(passNote);
    row.appendChild(cmdInput);
    row.appendChild(removeBtn);

    return row;
  }

  function renumberWolSshRows() {
    const rows = wolSshList.querySelectorAll(".ssh-row");
    rows.forEach((row, idx) => {
      const titleEl = row.querySelector(".ssh-row-title");
      if (titleEl) titleEl.textContent = `SSH Action #${idx + 1}`;
    });
  }

  wolSshAddBtn.addEventListener("click", () => {
    const row = createWolSshRow({ host: wolHostInput.value.trim() });
    wolSshList.appendChild(row);
    renumberWolSshRows();
  });

  function collectWolSshActions() {
    const actions = [];
    const rows = wolSshList.querySelectorAll(".ssh-row");
    rows.forEach(row => {
      const label = row.querySelector("input[data-field='label']").value.trim();
      const icon  = row.querySelector("input[data-field='icon']").value.trim();
      const user  = row.querySelector("input[data-field='user']").value.trim();
      const host  = row.querySelector("input[data-field='host']").value.trim();
      const pass  = row.querySelector("input[data-field='pass']").value;
      const cmd   = row.querySelector("input[data-field='command']").value.trim();
      if (!label || !user || !cmd) return;
      actions.push({
        label,
        icon,
        user,
        host,
        pass,
        command: cmd
      });
    });
    return actions;
  }

  function showModal(whichType, editId = null) {
    if (!editMode) return;

    mode.type   = whichType;
    mode.id     = editId;
    mode.action = editId ? "edit" : "create";

    overlay.classList.remove("hidden");

    if (whichType === "service") {
      showOnlyForm("service");
      if (mode.action === "edit") {
        const svc = state.services.find(s => s.id === mode.id);
        if (svc) {
          document.getElementById("svc-name").value     = svc.name || "";
          document.getElementById("svc-open").value     = svc.openUrl || "";
          svcMethodEl.value                             = svc.method || "http";
          document.getElementById("svc-check").value    = svc.checkUrl || "";
          document.getElementById("svc-notes").value    = svc.notes || "";
          updateSvcCheckLabel();
        }
      } else {
        resetServiceForm();
      }
    } else if (whichType === "link") {
      showOnlyForm("link");
      if (mode.action === "edit") {
        const lnk = state.links.find(l => l.id === mode.id);
        if (lnk) {
          document.getElementById("lnk-title").value = lnk.title || "";
          document.getElementById("lnk-url").value   = lnk.url   || "";
          document.getElementById("lnk-icon").value  = lnk.icon  || "";
          document.getElementById("lnk-notes").value = lnk.notes || "";
        }
      } else {
        resetLinkForm();
      }
    } else if (whichType === "wol") {
      showOnlyForm("wol");
      if (mode.action === "edit") {
        const task = state.wol.find(w => w.id === mode.id);
        if (task) {
          const typeEl = document.getElementById("wol-type");
          if (typeEl) typeEl.value = task.type || "basic";
          document.getElementById("wol-name").value   = task.name     || "";
          document.getElementById("wol-host").value   = task.host     || "";
          document.getElementById("wol-user").value   = task.user     || "";
          document.getElementById("wol-pass").value   = task.pass     || "";
          document.getElementById("wol-script").value = task.scriptId || "";
          document.getElementById("wol-notes").value  = task.notes    || "";
          if (wolCheckMethodEl) wolCheckMethodEl.value = task.statusMethod || "http";
          if (wolCheckInputEl) wolCheckInputEl.value = task.statusTarget || "";
          if (task.type === "wadesp") {
            document.getElementById("wol-esp-host").value  = task.espHost  || "";
            const tokEl = document.getElementById("wol-esp-token");
            if (tokEl) tokEl.value = task.espToken || "";
          }
          if (typeof updateWolTypeUI === "function") updateWolTypeUI();
          if (typeof updateWolCheckLabel === "function") updateWolCheckLabel();
          clearWolSshForm();
          if (Array.isArray(task.sshActions)) {
            task.sshActions.forEach(a => {
              const row = createWolSshRow(a);
              wolSshList.appendChild(row);
            });
            renumberWolSshRows();
          }
        }
      } else {
        resetWolForm();
      }
    } else if (whichType === "host") {
      showOnlyForm("host");
      if (mode.action === "edit") {
        const action = state.hostActions.find(a => a.id === mode.id);
        if (action) {
          hostLabelInput.value   = action.label || "";
          if (hostIconInput) hostIconInput.value = action.icon || "";
          hostCommandInput.value = action.command || "";
          hostNotesInput.value   = action.notes || "";
        }
      } else {
        resetHostForm();
      }
    }

    updateFormTitles();
  }

  function hideModal() {
    overlay.classList.add("hidden");
  }

  openBtn.addEventListener("click", () => showModal("service"));
  closeBtn.addEventListener("click", hideModal);

  tabSvcBtn.addEventListener("click", () => showModal("service", mode.action === "edit" ? mode.id : null));
  tabLnkBtn.addEventListener("click", () => showModal("link",    mode.action === "edit" ? mode.id : null));
  tabWolBtn.addEventListener("click", () => showModal("wol",     mode.action === "edit" ? mode.id : null));
  tabHostBtn.addEventListener("click", () => showModal("host",   mode.action === "edit" ? mode.id : null));

  // ==============================
  // FORM SUBMIT HANDLERS (CRUD)
  // ==============================
  formSvc.addEventListener("submit", async e => {
    e.preventDefault();
    if (!editMode) return;

    const body = {
      name:     document.getElementById("svc-name").value.trim(),
      openUrl:  document.getElementById("svc-open").value.trim(),
      method:   svcMethodEl.value,
      checkUrl: document.getElementById("svc-check").value.trim(),
      notes:    document.getElementById("svc-notes").value.trim()
    };
    if (!body.name || !body.openUrl || !body.checkUrl) return;

    if (mode.action === "edit" && mode.id) {
      await apiJSON("PUT", "/service/" + mode.id, body);
    } else {
      await apiJSON("POST", "/service", body);
    }

    hideModal();
    await loadStateFromServer();
  });

  formLnk.addEventListener("submit", async e => {
    e.preventDefault();
    if (!editMode) return;

    const body = {
      title: document.getElementById("lnk-title").value.trim(),
      url:   document.getElementById("lnk-url").value.trim(),
      icon:  document.getElementById("lnk-icon").value.trim(),
      notes: document.getElementById("lnk-notes").value.trim()
    };
    if (!body.title || !body.url) return;

    if (mode.action === "edit" && mode.id) {
      await apiJSON("PUT", "/link/" + mode.id, body);
    } else {
      await apiJSON("POST", "/link", body);
    }

    hideModal();
    await loadStateFromServer();
  });


formWol.addEventListener("submit", async e => {
  e.preventDefault();
  if (!editMode) return;

  const type = document.getElementById("wol-type").value;

  let body = {
    name: document.getElementById("wol-name").value.trim(),
    type,
    notes: document.getElementById("wol-notes").value.trim(),
    statusMethod: wolCheckMethodEl ? wolCheckMethodEl.value : "http",
    statusTarget: wolCheckInputEl ? wolCheckInputEl.value.trim() : "",
    sshActions: collectWolSshActions()
  };

  if (type === "basic") {
    body.mac       = document.getElementById("wol-mac").value.trim();
    body.broadcast = document.getElementById("wol-broadcast").value.trim();
    body.port      = document.getElementById("wol-port").value.trim();
    body.secureon  = document.getElementById("wol-secureon").value.trim();
    if (!body.mac) return;
  }

  if (type === "mikrotik") {
    body.host     = document.getElementById("wol-host").value.trim();
    body.user     = document.getElementById("wol-user").value.trim();
    body.pass     = document.getElementById("wol-pass").value.trim();
    body.scriptId = document.getElementById("wol-script").value.trim();
    if (!body.host || !body.user || !body.pass || !body.scriptId) return;
  }

  if (type === "wadesp") {
    body.espHost = document.getElementById("wol-esp-host").value.trim();
    if (!body.espHost) return;
  }

  if (mode.action === "edit" && mode.id) {
    await apiJSON("PUT", "/wol/" + mode.id, body);
  } else {
    await apiJSON("POST", "/wol", body);
  }

  hideModal();
  await loadStateFromServer();
});

  if (hostIconTrigger) {
    hostIconTrigger.addEventListener("click", () => {
      openIconPicker({
        input: hostIconInput
      });
    });
  }
  if (iconPickerCloseBtn) iconPickerCloseBtn.addEventListener("click", closeIconPicker);
  if (iconPickerSearchInput) {
    iconPickerSearchInput.addEventListener("input", () => {
      if (iconSearchDebounceTimer) clearTimeout(iconSearchDebounceTimer);
      iconSearchDebounceTimer = setTimeout(() => {
        runIconSearch(iconPickerSearchInput.value);
      }, 220);
    });
  }
  if (iconPickerOverlay) {
    iconPickerOverlay.addEventListener("click", (e) => {
      if (e.target === iconPickerOverlay) closeIconPicker();
    });
  }

if (brandSaveBtn) {
  brandSaveBtn.addEventListener("click", async () => {
    if (!editMode) return;
    const cleaned = sanitizeBrandText(brandTextInput ? brandTextInput.value : "");
    try {
      brandSaveBtn.disabled = true;
      if (brandSaveStatus) brandSaveStatus.textContent = "Saving...";

      const resp = await apiJSON("PUT", "/brand-text", { text: cleaned });
      if (resp && resp.ok) {
        brandText = sanitizeBrandText(resp.text) || "WELCOME";
        brandTextCustom = sanitizeBrandText(resp.custom || "");
        applyBrandText();
        loadBrandTextIntoForm();
        if (brandSaveStatus) brandSaveStatus.textContent = "Saved";
      } else {
        if (brandSaveStatus) brandSaveStatus.textContent = "Save failed";
      }
    } catch (e) {
      if (brandSaveStatus) brandSaveStatus.textContent = "Save failed";
    } finally {
      brandSaveBtn.disabled = false;
    }
  });
}



  formHost.addEventListener("submit", async e => {
    e.preventDefault();
    if (!editMode) return;

    const body = {
      label:   hostLabelInput.value.trim(),
      icon:    hostIconInput ? hostIconInput.value.trim() : "",
      command: hostCommandInput.value.trim(),
      notes:   hostNotesInput.value.trim()
    };
    if (!body.label || !body.command) return;

    if (mode.action === "edit" && mode.id) {
      await apiJSON("PUT", "/host-action/" + mode.id, body);
    } else {
      await apiJSON("POST", "/host-action", body);
    }

    hideModal();
    await loadStateFromServer();
  });

  // ==============================
  // DELETE HANDLERS (with confirm)
  // ==============================
  async function deleteService(id) {
    if (!editMode) return;
    const svc = state.services.find(s => s.id === id);
    const name = svc ? svc.name : id;
    const ok = window.confirm(`Delete service "${name}"? This cannot be undone.`);
    if (!ok) return;
    await apiDELETE("/service/" + id);
    await loadStateFromServer();
  }

  async function deleteLink(id) {
    if (!editMode) return;
    const lnk = state.links.find(l => l.id === id);
    const name = lnk ? lnk.title : id;
    const ok = window.confirm(`Delete link "${name}"? This cannot be undone.`);
    if (!ok) return;
    await apiDELETE("/link/" + id);
    await loadStateFromServer();
  }

  async function deleteWol(id) {
    if (!editMode) return;
    const task = state.wol.find(w => w.id === id);
    const name = task ? task.name : id;
    const ok = window.confirm(`Delete WOL task "${name}"? This cannot be undone.`);
    if (!ok) return;
    await apiDELETE("/wol/" + id);
    await loadStateFromServer();
  }

  async function deleteHostAction(id) {
    if (!editMode) return;
    const action = state.hostActions.find(a => a.id === id);
    const name = action ? action.label : id;
    const ok = window.confirm(`Delete device command "${name}"? This cannot be undone.`);
    if (!ok) return;
    await apiDELETE("/host-action/" + id);
    await loadStateFromServer();
  }

  // ==============================
  // WOL RUN / SSH RUN / HOST RUN
  // ==============================
  async function runWol(id) {
    const resp = await apiPOSTNoBody("/wol/" + id + "/run");
    if (resp && resp.ok) {
      showToast({ title: "WOL", message: "Executed successfully", type: "success" });
    } else {
      const err = formatActionError(resp);
      showToast({ title: "WOL", message: err.message, detail: err.detail, type: "error" });
    }
    await loadStateFromServer();
  }

  async function runWolSsh(wolId, actionId) {
    const resp = await apiPOSTNoBody(`/wol/${wolId}/ssh/${actionId}/run`);
    if (resp && resp.ok) {
      showToast({ title: "SSH Action", message: "Executed successfully", type: "success" });
    } else {
      const err = formatActionError(resp);
      showToast({ title: "SSH Action", message: err.message, detail: err.detail, type: "error" });
    }
    await loadStateFromServer();
  }

  async function runHostAction(id) {
    const resp = await apiPOSTNoBody(`/host-action/${id}/run`);
    if (resp && resp.ok) {
      showToast({ title: "Device Command", message: "Executed successfully", type: "success" });
    } else {
      const err = formatActionError(resp);
      showToast({ title: "Device Command", message: err.message, detail: err.detail, type: "error" });
    }
    await loadStateFromServer();
  }

  // ==============================
  // DRAG & DROP (reorder)
  // ==============================
  let dragSvcIdx = null;
  let dragLnkIdx = null;
  let dragWolIdx = null;

  function bindDrag(containerId, type, arr, persistFn) {
    const cont  = document.getElementById(containerId);
    const cards = Array.from(cont.querySelectorAll(`.card[data-type='${type}']`));

    cards.forEach((card, idx) => {
      if (editMode) {
        card.setAttribute("draggable", "true");
      } else {
        card.removeAttribute("draggable");
      }

      card.dataset.index = idx;

      card.addEventListener("dragstart", e => {
        if (!editMode) return;
        if (type === "service")      dragSvcIdx = idx;
        else if (type === "link")    dragLnkIdx = idx;
        else                         dragWolIdx = idx;
        e.dataTransfer.effectAllowed = "move";
      });

      card.addEventListener("dragover", e => {
        if (!editMode) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        card.classList.add("drag-over");
      });

      card.addEventListener("dragleave", () => {
        card.classList.remove("drag-over");
      });

      card.addEventListener("drop", async e => {
        if (!editMode) return;
        e.preventDefault();
        card.classList.remove("drag-over");

        const from = (type === "service") ? dragSvcIdx
                    : (type === "link")   ? dragLnkIdx
                    : dragWolIdx;
        const to = Number(card.dataset.index);

        if (Number.isInteger(from) && from !== to) {
          const moved = arr.splice(from, 1)[0];
          arr.splice(to, 0, moved);

          await persistFn();
          await loadStateFromServer();
        }

        if (type === "service")      dragSvcIdx = null;
        else if (type === "link")    dragLnkIdx = null;
        else                         dragWolIdx = null;
      });
    });
  }

  // ==============================
  // RENDER
  // ==============================
  function render() {
    svcCount.textContent = state.services.length + " total";
    lnkCount.textContent = state.links.length + " total";
    wolCount.textContent = state.wol.length + " total";

    // services grid
    svcGrid.innerHTML = state.services.length
      ? ""
      : `<div style="color:var(--text-dim); font-size:.85rem;">No services yet</div>`;

    state.services.forEach(s => {
      const card = renderServiceCard(s);
      svcGrid.appendChild(card);
    });
    if (state.services.length % 2 === 1 && state.services.length > 0) {
      const lastCard = svcGrid.lastElementChild;
      if (lastCard) lastCard.classList.add("full-span");
    }

    // links grid
    lnkGrid.innerHTML = state.links.length
      ? ""
      : `<div style="color:var(--text-dim); font-size:.85rem;">No links yet</div>`;

    state.links.forEach(l => {
      const card = renderLinkCard(l);
      lnkGrid.appendChild(card);
    });
    if (state.links.length % 2 === 1 && state.links.length > 0) {
      const lastCard = lnkGrid.lastElementChild;
      if (lastCard) lastCard.classList.add("full-span");
    }

    // wol grid
    wolGrid.innerHTML = state.wol.length
      ? ""
      : `<div style="color:var(--text-dim); font-size:.85rem;">No WOL yet</div>`;

    state.wol.forEach(w => {
      const card = renderWolCard(w);
      wolGrid.appendChild(card);
    });
    if (state.wol.length % 2 === 1 && state.wol.length > 0) {
      const lastCard = wolGrid.lastElementChild;
      if (lastCard) lastCard.classList.add("full-span");
    }

    // host actions in banner
    renderHostActions();

    bindDrag("svc-grid", "service", state.services, persistOrderServices);
    bindDrag("lnk-grid", "link", state.links, persistOrderLinks);
    bindDrag("wol-grid", "wol", state.wol, persistOrderWOL);
  }

  function renderServiceCard(s) {
    const card = document.createElement("div");
    card.className = "card";
    card.dataset.type = "service";

    const top = document.createElement("div");
    top.className = "svc-top";

    const left = document.createElement("div");

    const nameWrap = document.createElement("div");
    nameWrap.className = "svc-name";

    const spanName = document.createElement("span");
    spanName.textContent = s.name;

    const spanChip = document.createElement("span");
    spanChip.className = (s.lastStatus === "UP") ? "chip-up" : "chip-down";
    spanChip.textContent = s.lastStatus || "unknown";

    nameWrap.appendChild(spanName);
    nameWrap.appendChild(spanChip);

    const urlEl = document.createElement("div");
    urlEl.className = "svc-url";
    urlEl.textContent = s.openUrl;

    left.appendChild(nameWrap);
    left.appendChild(urlEl);

    if (s.notes) {
      const notesEl = document.createElement("div");
      notesEl.className = "svc-notes";
      notesEl.textContent = s.notes;
      left.appendChild(notesEl);
    }

    const right = document.createElement("div");
    right.className = "btn-row";

    const openBtn = document.createElement("a");
    openBtn.className = "btn";
    openBtn.href = s.openUrl;
    openBtn.target = "_blank";
    openBtn.rel = "noopener";
    setLinkContentWithOptionalIcon(openBtn, "external-link", `Open ${s.name}`);
    right.appendChild(openBtn);

    if (editMode) {
      const editBtn = document.createElement("button");
      editBtn.className = "btn btn-edit btn-icon-only";
      editBtn.innerHTML = ICON_BTN_EDIT;
      editBtn.setAttribute("aria-label", "Edit");
      editBtn.title = "Edit";
      editBtn.onclick = () => showModal("service", s.id);
      right.appendChild(editBtn);

      const delBtn = document.createElement("button");
      delBtn.className = "btn btn-danger btn-icon-only";
      delBtn.innerHTML = ICON_BTN_DELETE;
      delBtn.setAttribute("aria-label", "Delete");
      delBtn.title = "Delete";
      delBtn.onclick = () => deleteService(s.id);
      right.appendChild(delBtn);
    }

    top.appendChild(left);
    top.appendChild(right);

    const meta = document.createElement("div");
    meta.className = "meta";

    const g1 = document.createElement("div");
    g1.className = "group";
    g1.innerHTML = `<b>Last check</b>${fmt(s.lastChecked)}`;

    meta.appendChild(g1);

    card.appendChild(top);
    card.appendChild(meta);

    return card;
  }

  function renderLinkCard(l) {
    const card = document.createElement("div");
    card.className = "card";
    card.dataset.type = "link";

    const row = document.createElement("div");
    row.className = "link-row";

    const left = document.createElement("div");
    left.className = "link-left";

    const iconEl = document.createElement("div");
    iconEl.className = "link-icon";
    iconEl.textContent = l.icon || "🔗";

    const txtWrap = document.createElement("div");

    const titleEl = document.createElement("div");
    titleEl.className = "link-title";
    titleEl.textContent = l.title;

    const urlEl = document.createElement("div");
    urlEl.className = "link-url";
    urlEl.textContent = l.url;

    txtWrap.appendChild(titleEl);
    txtWrap.appendChild(urlEl);

    if (l.notes) {
      const notesEl = document.createElement("div");
      notesEl.className = "link-notes";
      notesEl.textContent = l.notes;
      txtWrap.appendChild(notesEl);
    }

    left.appendChild(iconEl);
    left.appendChild(txtWrap);

    const right = document.createElement("div");
    right.className = "btn-row";

    const openBtn = document.createElement("a");
    openBtn.className = "btn";
    openBtn.href = l.url;
    openBtn.target = "_blank";
    openBtn.rel = "noopener";
    setLinkContentWithOptionalIcon(openBtn, "link", `Open ${l.title}`);
    right.appendChild(openBtn);

    if (editMode) {
      const editBtn = document.createElement("button");
      editBtn.className = "btn btn-edit btn-icon-only";
      editBtn.innerHTML = ICON_BTN_EDIT;
      editBtn.setAttribute("aria-label", "Edit");
      editBtn.title = "Edit";
      editBtn.onclick = () => showModal("link", l.id);
      right.appendChild(editBtn);

      const delBtn = document.createElement("button");
      delBtn.className = "btn btn-danger btn-icon-only";
      delBtn.innerHTML = ICON_BTN_DELETE;
      delBtn.setAttribute("aria-label", "Delete");
      delBtn.title = "Delete";
      delBtn.onclick = () => deleteLink(l.id);
      right.appendChild(delBtn);
    }

    row.appendChild(left);
    row.appendChild(right);

    card.appendChild(row);
    return card;
  }

  function renderWolCard(w) {
    const card = document.createElement("div");
    card.className = "card";
    card.dataset.type = "wol";

    const row = document.createElement("div");
    row.className = "wol-row";

    const left = document.createElement("div");
    left.className = "wol-left";

    const nameWrap = document.createElement("div");
    nameWrap.className = "svc-name";

    const titleEl = document.createElement("span");
    titleEl.className = "wol-title";
    titleEl.textContent = w.name;

    const statusEl = document.createElement("span");
    const statusText = w.lastStatus || "unknown";
    statusEl.className = statusText === "UP" ? "chip-up" : "chip-down";
    statusEl.textContent = statusText;

    nameWrap.appendChild(titleEl);
    nameWrap.appendChild(statusEl);

    const metaEl = document.createElement("div");
    metaEl.className = "wol-meta";
    const chip = `<span class="wol-chip">${w.lastResult || "never"}</span>`;
    metaEl.innerHTML = chip + "  Last run: " + fmt(w.lastRun);

    left.appendChild(nameWrap);

    if (w.notes) {
      const notesEl = document.createElement("div");
      notesEl.className = "wol-notes";
      notesEl.textContent = w.notes;
      left.appendChild(notesEl);
    }

    left.appendChild(metaEl);

    const right = document.createElement("div");
    right.className = "btn-row";

    // Run WOL always visible, password-protected when not in edit mode
    const runBtn = document.createElement("button");
    runBtn.className = "btn";
    setButtonContentWithOptionalIcon(runBtn, "play", `Run ${w.name}`);
    runBtn.onclick = () => ensureAdminThen(() => runWol(w.id));
    right.appendChild(runBtn);

    // SSH actions always visible, password-protected when not in edit mode
    if (Array.isArray(w.sshActions)) {
      w.sshActions.forEach(a => {
        const sshBtn = document.createElement("button");
        sshBtn.className = "btn";
        setButtonContentWithOptionalIcon(sshBtn, a.icon, a.label || "SSH");
        sshBtn.onclick = () => ensureAdminThen(() => runWolSsh(w.id, a.id));
        right.appendChild(sshBtn);
      });
    }

    // Edit/delete only in edit mode
    if (editMode) {
      const editBtn = document.createElement("button");
      editBtn.className = "btn btn-edit btn-icon-only";
      editBtn.innerHTML = ICON_BTN_EDIT;
      editBtn.setAttribute("aria-label", "Edit");
      editBtn.title = "Edit";
      editBtn.onclick = () => showModal("wol", w.id);
      right.appendChild(editBtn);

      const delBtn = document.createElement("button");
      delBtn.className = "btn btn-danger btn-icon-only";
      delBtn.innerHTML = ICON_BTN_DELETE;
      delBtn.setAttribute("aria-label", "Delete");
      delBtn.title = "Delete";
      delBtn.onclick = () => deleteWol(w.id);
      right.appendChild(delBtn);
    }

    row.appendChild(left);
    row.appendChild(right);

    card.appendChild(row);
    return card;
  }

  function renderHostActions() {
    const container = document.getElementById("host-actions");
    if (!container) return;

    container.innerHTML = "";

    if (!state.hostActions || state.hostActions.length === 0) {
      const span = document.createElement("span");
      span.className = "host-actions-note";
      span.textContent = editMode
        ? "No maintenance commands yet"
        : "No maintenance commands available";
      container.appendChild(span);

      if (editMode) {
        const addBtn = document.createElement("button");
        addBtn.type = "button";
        addBtn.className = "icon-btn host-add-btn";
        addBtn.innerHTML = ICON_BTN_PLUS;
        addBtn.style.marginLeft = "0.5rem";
        addBtn.setAttribute("aria-label", "Add command");
        addBtn.title = "Add command";
        addBtn.onclick = () => {
          mode.action = "create";
          mode.id = null;
          showModal("host");
        };
        container.appendChild(addBtn);
      }
      return;
    }

    state.hostActions.forEach(action => {
      const wrap = document.createElement("div");
      wrap.style.display = "flex";
      wrap.style.flexWrap = "wrap";
      wrap.style.gap = "0.25rem";
      wrap.style.alignItems = "center";
      wrap.style.justifyContent = "center";

      const runBtn = document.createElement("button");
      runBtn.className = "btn";
      setButtonContentWithOptionalIcon(runBtn, action.icon, action.label || "Command");
      runBtn.onclick = () => ensureAdminThen(() => runHostAction(action.id));
      wrap.appendChild(runBtn);

      if (editMode) {
        const editBtn = document.createElement("button");
        editBtn.className = "btn btn-edit btn-icon-only";
        editBtn.innerHTML = ICON_BTN_EDIT;
        editBtn.setAttribute("aria-label", "Edit");
        editBtn.title = "Edit";
        editBtn.onclick = () => {
          mode.action = "edit";
          mode.id = action.id;
          showModal("host", action.id);
        };
        wrap.appendChild(editBtn);

        const delBtn = document.createElement("button");
        delBtn.className = "btn btn-danger btn-icon-only";
        delBtn.innerHTML = ICON_BTN_DELETE;
        delBtn.setAttribute("aria-label", "Delete");
        delBtn.title = "Delete";
        delBtn.onclick = () => deleteHostAction(action.id);
        wrap.appendChild(delBtn);
      }

      container.appendChild(wrap);
    });

    if (editMode) {
      const addBtn = document.createElement("button");
      addBtn.type = "button";
      addBtn.className = "icon-btn host-add-btn";
      addBtn.innerHTML = ICON_BTN_PLUS;
      addBtn.setAttribute("aria-label", "Add command");
      addBtn.title = "Add command";
      addBtn.onclick = () => {
        mode.action = "create";
        mode.id = null;
        showModal("host");
      };
      container.appendChild(addBtn);
    }
  }

  // ==============================
  // HOST INFO
  // ==============================
  function fmtShort(ts){
    if (!ts) return "—";
    const d = new Date(ts);
    const pad = n => String(n).padStart(2,"0");
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  async function loadHostInfo() {
    try {
      const res = await fetch(API_BASE + "/hostinfo", { credentials: "include" });
      const info = await res.json();

      const upd = document.getElementById("host-updated");
      const box = document.getElementById("host-stats");
      if (!box) return;

      const chips = [];

      if (info.ip) chips.push(`<span class="host-chip"><b>IP</b>${info.ip}</span>`);
      if (Number.isFinite(info.rssi)) chips.push(`<span class="host-chip"><b>RSSI</b>${info.rssi} dBm</span>`);
      if (info.ssid) chips.push(`<span class="host-chip"><b>SSID</b>${info.ssid}</span>`);
      if (info.health) chips.push(`<span class="host-chip"><b>Battery</b>${info.health}</span>`);
      if (info.status) chips.push(`<span class="host-chip"><b>Status</b>${info.status}</span>`);
      if (Number.isFinite(info.temperature)) chips.push(`<span class="host-chip"><b>Temp</b>${info.temperature}°C</span>`);
      if (Number.isFinite(info.percentage)) chips.push(`<span class="host-chip"><b>Charge</b>${info.percentage}%</span>`);

      if (!chips.length) {
        const reason = info.lastError ? String(info.lastError) : "no_data";
        chips.push(`<span class="host-chip">No data</span>`);
        chips.push(`<span class="host-chip"><b>Reason</b>${reason}</span>`);
      }

      box.innerHTML = chips.join("");

      upd.textContent = info.ok
        ? `Updated ${fmtShort(info.updatedAt)}`
        : `Last attempt ${fmtShort(info.updatedAt)} — ${info.lastError || "error"}`;
    } catch {
      const upd = document.getElementById("host-updated");
      const box = document.getElementById("host-stats");
      if (upd) upd.textContent = "Host info unavailable";
      if (box) box.innerHTML = `<span class="host-chip">No data</span>`;
    }
  }

  // ==============================
  // MANUAL REFRESH BUTTON
  // ==============================
  refreshBtn.addEventListener("click", async () => {
    try {
      refreshBtn.disabled = true;
      refreshBtn.setAttribute("aria-busy", "true");
      refreshBtn.title = "Refreshing...";
      await apiPOSTNoBody("/refresh");
      await loadStateFromServer();
      await loadHostInfo();
    } finally {
      refreshBtn.disabled = false;
      refreshBtn.setAttribute("aria-busy", "false");
      refreshBtn.title = "Refresh";
    }
  });

  // ==============================
  // AUTO REFRESH
  // ==============================
  async function refreshLoop() {
    await loadStateFromServer();
  }

  // ==============================
  // HEALTH PAGE
  // ==============================
  function showHomeUI() {
    if (homePage) homePage.classList.remove("hidden");
    if (healthPage) healthPage.classList.add("hidden");
  }

  function showHealthUI() {
    if (homePage) homePage.classList.add("hidden");
    if (healthPage) healthPage.classList.remove("hidden");
  }

  function fmtBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n)) return "—";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let v = n;
    let u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    const digits = u === 0 ? 0 : (v >= 100 ? 0 : v >= 10 ? 1 : 2);
    return `${v.toFixed(digits)} ${units[u]}`;
  }

  function fmtUptime(seconds) {
    const s = Math.max(0, Math.floor(Number(seconds) || 0));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function setBar(el, pct) {
    if (!el) return;
    const p = Number.isFinite(Number(pct)) ? Number(pct) : 0;
    const clamped = Math.max(0, Math.min(100, p));
    el.style.width = `${clamped}%`;
  }

  function setRing(circleEl, pct) {
    if (!circleEl) return;
    const p = Number.isFinite(Number(pct)) ? Number(pct) : 0;
    const clamped = Math.max(0, Math.min(100, p));
    const r = 52;
    const c = 2 * Math.PI * r;
    circleEl.style.strokeDasharray = `${c}`;
    circleEl.style.strokeDashoffset = `${c * (1 - clamped / 100)}`;

    if (clamped >= 85) circleEl.style.stroke = "#ef4444";
    else if (clamped >= 60) circleEl.style.stroke = "#f59e0b";
    else circleEl.style.stroke = "#10b981";
  }

  function showHealthError(text) {
    if (!healthErrorEl) return;
    if (!text) {
      healthErrorEl.classList.add("hidden");
      healthErrorEl.textContent = "";
      return;
    }
    healthErrorEl.classList.remove("hidden");
    healthErrorEl.textContent = text;
  }

  async function loadHealthOnce() {
    const res = await fetch("/api/health", { cache: "no-store" });
    if (res.status === 401) {
      await handleUnauthorizedResponse();
      throw new Error("access_required");
    }
    const j = await res.json().catch(() => null);
    if (!res.ok || !j || !j.ok) {
      throw new Error((j && j.error) ? j.error : `HTTP ${res.status}`);
    }
    return j;
  }

  function setHint(el, hint) {
    if (!el) return;
    el.textContent = hint ? String(hint) : "";
  }

  async function renderHealth() {
    try {
      const data = await loadHealthOnce();
      showHealthError("");

      if (healthUpdatedEl) healthUpdatedEl.textContent = `Updated ${fmtShort(data.updatedAt)}`;

      if (healthHostnameEl) healthHostnameEl.textContent = data.system?.hostname || "—";
      if (healthOsEl) {
        const osLine = [data.system?.platform, data.system?.release, data.system?.arch]
          .filter(Boolean)
          .join(" ");
        healthOsEl.textContent = osLine || "—";
      }
      if (healthUptimeEl) healthUptimeEl.textContent = fmtUptime(data.system?.uptimeSec);
      if (healthIpEl) healthIpEl.textContent = data.network?.ipv4 || "—";

      const cpuPct = data.cpu?.usagePercent;
      if (healthCpuPctEl) healthCpuPctEl.textContent = Number.isFinite(cpuPct) ? `${cpuPct}%` : "—%";
      if (healthCpuLoadEl) {
        const la = Array.isArray(data.cpu?.loadavg) ? data.cpu.loadavg : [];
        const loadText = la.length ? la.slice(0, 3).map(v => Number(v).toFixed(2)).join(" / ") : "—";
        healthCpuLoadEl.textContent = loadText;
      }
      setRing(healthCpuRingEl, Number.isFinite(cpuPct) ? cpuPct : 0);
      const cpuHint = data.cpu?.hint || (Number.isFinite(cpuPct) ? "" : "CPU usage unavailable");
      setHint(healthCpuNoteEl, cpuHint);

      const memPct = data.memory?.usedPercent;
      setBar(healthRamBarEl, Number.isFinite(memPct) ? memPct : 0);
      if (healthRamTextEl) {
        const used = fmtBytes(data.memory?.usedBytes);
        const total = fmtBytes(data.memory?.totalBytes);
        const pctText = Number.isFinite(memPct) ? `${memPct}%` : "—%";
        healthRamTextEl.textContent = `${used} / ${total} (${pctText})`;
      }
      setHint(healthRamNoteEl, Number.isFinite(memPct) ? "" : "Memory usage unavailable");

      const storage = data.storage || data.disk || null;
      if (storage?.available) {
        const diskPct = storage?.usedPercent;
        setBar(healthDiskBarEl, Number.isFinite(diskPct) ? diskPct : 0);
        if (healthDiskTextEl) {
          const used = fmtBytes(storage?.usedBytes);
          const total = fmtBytes(storage?.totalBytes);
          const pctText = Number.isFinite(diskPct) ? `${diskPct}%` : "—%";
          const where = storage?.mount || storage?.path || "";
          healthDiskTextEl.textContent = where
            ? `${used} / ${total} (${pctText}) — ${where}`
            : `${used} / ${total} (${pctText})`;
        }
        setHint(healthDiskNoteEl, "");
      } else {
        setBar(healthDiskBarEl, 0);
        if (healthDiskTextEl) healthDiskTextEl.textContent = "Unavailable";
        setHint(healthDiskNoteEl, storage?.hint || "Storage info unavailable");
      }

      if (data.battery?.available) {
        const pct = data.battery?.percent;
        const st = data.battery?.status;
        const pctText = Number.isFinite(pct) ? `${pct}%` : "—%";
        if (healthBatteryEl) healthBatteryEl.textContent = st ? `${pctText} (${st})` : pctText;
        setHint(healthSysNoteEl, "");
      } else {
        if (healthBatteryEl) healthBatteryEl.textContent = "Unavailable";
        setHint(healthSysNoteEl, data.battery?.hint || "");
      }
    } catch (e) {
      if (e && e.message === "access_required") return;
      showHealthError(`Health API unavailable: ${e && e.message ? e.message : e}`);
    }
  }

  async function initHealthPage() {
    if (healthRefreshBtn) {
      healthRefreshBtn.addEventListener("click", async () => {
        healthRefreshBtn.disabled = true;
        healthRefreshBtn.setAttribute("aria-busy", "true");
        healthRefreshBtn.title = "Refreshing...";
        try {
          await renderHealth();
        } finally {
          healthRefreshBtn.disabled = false;
          healthRefreshBtn.setAttribute("aria-busy", "false");
          healthRefreshBtn.title = "Refresh";
        }
      });
    }

    await renderHealth();
    setInterval(renderHealth, 10000);
  }

  // ==============================
  // INIT
  // ==============================
  async function startApp() {
    if (appStarted) return;
    appStarted = true;

    await refreshBrandTextFromServer();

    if (isHealthRoute) {
      showHealthUI();
      await initHealthPage();
      return;
    }

    showHomeUI();
    openBtn.classList.add("hidden");
    // updateBatteryFormDisabled();

    const adminStatus = await fetch("/api/admin/status").then(r => r.json());
    if (!adminStatus.initialized) {
      adminOverlay.classList.remove("hidden");
      adminPassInput.placeholder = "Set admin password";
      if (adminStatusEl) {
        adminStatusEl.textContent = "Set a new admin password (min 6 characters).";
        adminStatusEl.classList.remove("error");
      }
    }


    await loadStateFromServer();
    await loadHostInfo();

    setInterval(refreshLoop, 10000);
    setInterval(loadHostInfo, 60000);
  }

  (async function init() {
    const status = await loadAccessStatus();
    if (status.privateMode && !status.authorized) {
      showAccessOverlay("");
      return;
    }
    hideAccessOverlay();
    await startApp();
  })();





// ==============================
// WOL TYPE SWITCH
// ==============================
const wolTypeSelect = document.getElementById("wol-type");
const wolBasicBox   = document.getElementById("wol-basic");
const wolMikrotikBox= document.getElementById("wol-mikrotik");
const wolWadEspBox  = document.getElementById("wol-wadesp");
const wolSshSection = document.getElementById("wol-ssh-section");

function updateWolTypeUI() {
  const t = wolTypeSelect.value;

  wolBasicBox.classList.add("hidden");
  wolMikrotikBox.classList.add("hidden");
  wolWadEspBox.classList.add("hidden");

  if (t === "basic") {
    wolBasicBox.classList.remove("hidden");
  }

  if (t === "mikrotik") {
    wolMikrotikBox.classList.remove("hidden");
  }

  if (t === "wadesp") {
    wolWadEspBox.classList.remove("hidden");
  }
}


wolTypeSelect.addEventListener("change", updateWolTypeUI);
updateWolTypeUI();


const pwdOldInput   = document.getElementById("pwd-old");
const pwdNewInput   = document.getElementById("pwd-new");
const pwdSaveBtn    = document.getElementById("pwd-save-btn");
const pwdSaveStatus = document.getElementById("pwd-save-status");

pwdSaveBtn.addEventListener("click", async () => {
  if (!editMode) return;

  const oldPw = pwdOldInput.value.trim();
  const newPw = pwdNewInput.value.trim();

  if (!newPw || newPw.length < 6) {
    pwdSaveStatus.textContent = "Password too short";
    return;
  }

  pwdSaveStatus.textContent = "Saving...";

  const res = await apiJSON("PUT", "/admin/password", {
    oldPassword: oldPw,
    newPassword: newPw
  });

  if (res && res.ok) {
    pwdSaveStatus.textContent = "Password changed";
    pwdOldInput.value = "";
    pwdNewInput.value = "";
  } else {
    pwdSaveStatus.textContent = "Wrong current password";
  }
});

