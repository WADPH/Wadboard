# Wadboard

Wadboard is a self-hosted infrastructure dashboard for internal environments. It combines service monitoring, quick links, Wake-on-LAN and remote device actions, host health metrics, a browser terminal, and lightweight admin controls in a single project with a static frontend and a Node.js backend.
<details>
   <summary>Click to expand</summary>
<img width="1245" height="1001" alt="image" src="https://github.com/user-attachments/assets/26392fee-beba-432e-bf2f-21f0db1db4c0" />
</details>

## Table of Contents

- [Wadboard](#wadboard)
  - [What it does](#what-it-does)
  - [Architecture](#architecture)
  - [Core features](#core-features)
    - [Service Monitoring](#service-monitoring)
    - [Quick Links](#quick-links)
    - [Wake-on-LAN and Power Actions](#wake-on-lan-and-power-actions)
    - [SSH Actions](#ssh-actions)
    - [Host Maintenance Commands](#host-maintenance-commands)
    - [Health and Host Metrics](#health-and-host-metrics)
    - [Battery Monitoring](#battery-monitoring)
    - [Admin Session and Private Mode](#admin-session-and-private-mode)
    - [Config Import / Export](#config-import--export)
    - [Logs and Audit Trail](#logs-and-audit-trail)
    - [Browser Terminal](#browser-terminal)
  - [Security model](#security-model)
    - [View mode](#view-mode)
    - [Private mode](#private-mode)
    - [Admin mode](#admin-mode)
  - [Requirements](#requirements)
    - [Required](#required)
    - [Optional but feature-dependent](#optional-but-feature-dependent)
  - [Installation](#installation)
    - [1. Clone the repository](#1-clone-the-repository)
    - [2. Install backend dependencies](#2-install-backend-dependencies)
    - [3. Start the backend](#3-start-the-backend)
    - [4. Open in browser](#4-open-in-browser)
  - [Logging](#logging)
  - [Project structure](#project-structure)
  - [Notes](#notes)


## What it does

- Monitor services with HTTP(S) or ping checks
- Store and launch quick links
- Run Wake-on-LAN tasks using:
  - Basic WOL via local `wol`
  - MikroTik script execution via REST
  - WadESP-PowerSW HTTP trigger
- Attach SSH actions to WOL entries
- Run local host maintenance commands
- Show host info and health metrics
- Open an admin-protected browser terminal
- Support brand text customization
- Support private mode with long-lived view sessions
- Export and import dashboard configuration
- Keep audit and backend logs in `wadboard_backend.log`

## Architecture

- Frontend: static SPA served from `frontend/`
- Backend: Express server started with `node server.js`
- Storage: local JSON file `backend/wadph-data.json`
- Logging: shared backend logger writing to stdout/stderr and `backend/wadboard_backend.log`
- Database: no external DB, no cloud dependency

## Core features

### Service Monitoring

- HTTP(S) or ping health checks
- Automatic refresh
- UP / DOWN state tracking
- Notes per service

### Quick Links

- Link cards with title, URL, icon and notes

### Wake-on-LAN and Power Actions

- Basic WOL with MAC, broadcast, port and SecureON
- MikroTik-based power-on via RouterOS REST script execution
- WadESP-PowerSW trigger via `POST /power/on`

### SSH Actions

- SSH actions can be attached to any WOL task
- Supports key-based and password-based flows
- Password-based mode requires `sshpass`

### Host Maintenance Commands

- Run local commands on the host where Wadboard is running
- Intended for maintenance, restart, diagnostics and similar actions

### Health and Host Metrics

- Home page host info banner
- Dedicated `/health` page
- CPU, memory, storage, uptime, network and battery information when available
- Graceful degradation when some metrics are unavailable

### Battery Monitoring

- Optional battery polling
- Telegram low-battery alerts
- Multiple thresholds supported, for example `30,15,5`

### Admin Session and Private Mode

- Admin password is initialized on first login
- Admin sessions are cookie-based and in-memory
- Private mode can require access authentication before dashboard viewing
- View sessions can be listed and revoked from Settings

### Config Import / Export

- Export current config from Settings
- Import compatible JSON config from Settings
- Structure is validated before import
- Existing `wadph-data.json` is backed up by renaming it to `$date-wadph-data.json`
- Imported configs are normalized for backward compatibility where possible

### Logs and Audit Trail

- Unified backend logger
- Timestamped log levels:
  - `INFO`
  - `WARN`
  - `ERROR`
  - `AUDIT`
- Log viewer in Settings for admins
- Audit entries cover important actions such as:
  - admin login/logout
  - private mode changes
  - WOL execution
  - SSH action execution
  - host action execution
  - config import
  - create/update/delete operations for main entities

### Browser Terminal

- WebSocket terminal endpoint at `/api/terminal`
- Admin-protected
- Uses local shell and `script` when available

## Security model

### View mode

- Default browsing mode
- Read-only UI
- If private mode is disabled, dashboard pages are viewable without extra login

### Private mode

- Requires password-based access to view dashboard pages
- Applies to both `/` and `/health`
- Uses long-lived view-session cookies

### Admin mode

- Required for editing, maintenance actions, terminal access, config import/export and log viewing
- Password hash is stored in `wadph-data.json`
- Admin sessions are stored in memory and expire automatically

## Requirements

### Required

- Node.js 18+
- `ping` available in PATH for ping-based checks

### Optional but feature-dependent

- `wol` for Basic WOL
- `sshpass` for password-based SSH actions
- `script` from util-linux for better terminal behavior
- Termux and `termux-api` for richer Android host integration
- MikroTik RouterOS REST API for MikroTik WOL mode
- Telegram bot token and chat ID for battery alerts

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/WADPH/wadboard.git
cd wadboard
```

### 2. Install backend dependencies

```bash
cd backend
npm ci
```

### 3. Start the backend manually

Manually
```bash
node server.js
```

With pm2
```bash
cd .. # Go to the root folder
./init.pm2.sh
```

The backend listens on port `4000` by default and serves the frontend from `../frontend`.

### 4. Open in browser

- `http://localhost:4000/`
- `http://localhost:4000/health`

On first admin login, Wadboard will ask you to set the admin password.

## Logging

Backend logs are written to:

- `backend/wadboard_backend.log`

The log file includes startup messages, errors, warnings and audit events with timestamps.

## Project structure

```text
.
├── LICENSE
├── README.md
├── backend
│   ├── package-lock.json
│   ├── package.json
│   ├── server.js
│   ├── wadboard_backend.log
│   ├── wadph-data.json
│   └── src
│       ├── actions.js
│       ├── auth.js
│       ├── config.js
│       ├── db.js
│       ├── health.js
│       ├── logger.js
│       ├── routes.js
│       └── terminal.js
└── frontend
    ├── index.html
    ├── assets
    │   ├── app.js
    │   └── styles.css
    └── images
        └── wadboard_logo.png
```

## Notes

- Wadboard is intended for trusted internal networks.
- It should not be exposed directly to the public internet without an additional reverse proxy and access hardening.
- Some features are host-dependent and degrade gracefully if the underlying tools are not installed.
