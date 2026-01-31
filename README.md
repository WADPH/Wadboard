# Wadboard — Your Own Lightweight Infrastructure Dashboard

<img width="967" height="1003" alt="Wadboard screenshot" src="https://github.com/user-attachments/assets/eb055ea7-3c05-4442-a678-cdc8c4bd7f88" />

Wadboard is a self-hosted, minimalistic dashboard designed to monitor internal services, manage quick links, and remotely control devices (Wake-on-LAN, SSH actions, power relays).

The project is intentionally simple:
- single HTML frontend
- Node.js backend
- no external database
- no cloud dependencies

Everything runs locally and is fully under your control.

---

## Core Features

### 🔍 Service Monitoring
- HTTP(S) or ICMP (ping) health checks
- Automatic status refresh
- Visual UP / DOWN indicators
- Optional notes per service

### 🔗 Quick Links
- Group all internal services in one place
- Custom icons (emoji or text)
- Notes and descriptions

### ⚡ Remote Power & Wake-on-LAN
Wadboard supports multiple WOL / power-on methods:

- **Basic WOL**
  - Uses local `wol` binary
  - Broadcast, port and SecureON supported

- **MikroTik WOL**
  - Executes RouterOS scripts via REST API
  - Optional SSH actions per task

- **WadESP-PowerSW**
  - Simple HTTP-controlled ESP8266/ESP32 relay
  - Designed to emulate a physical PC power button

### 🔐 SSH Actions
- Attach arbitrary SSH commands to WOL tasks
- Can be used for:
  - shutdown
  - reboot
  - power-off smart PDUs
- Available for **all WOL types**, not only MikroTik

### 🖥️ Host Maintenance Commands
- Execute commands directly on the Wadboard host (e.g. Termux)
- Useful for:
  - rebooting the dashboard device
  - maintenance scripts
  - diagnostics

### 🔋 Battery Monitoring (Optional)
- For Termux hosts with `termux-api`
- Periodic battery status polling
- Telegram alerts on low battery thresholds

### 🔑 Secure Edit Mode
- No hardcoded admin password
- Password is set on first login
- Editing is locked behind an **admin session**
- View mode is always read-only and safe

---

## Philosophy

Wadboard is built for:
- homelabs
- small internal networks
- air-gapped or local-only environments

It is **not** intended to be exposed directly to the internet without a reverse proxy and additional protection.

## Requirements

### Backend
- Node.js **18+** (LTS recommended)
- `ping` binary available in PATH
  - `iputils-ping`, `inetutils-ping` or BusyBox
- Linux / Termux recommended

### Optional Integrations
- **MikroTik RouterOS v7**
  - REST API enabled
- **Telegram Bot**
  - For battery alerts
- **Termux + termux-api**
  - For host info and battery monitoring
- **ESP8266 / ESP32**
  - For WadESP-PowerSW

---

## Installation

### 1. Install system dependencies
```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y nodejs npm iputils-ping
```

### 2. Clone the repository
```bash
# Debian / Ubuntu
git clone https://github.com/WADPH/wadboard.git
cd wadboard
```

### 3. Install backend dependencies
```bash
# Debian / Ubuntu
cd backend
npm ci
# or
npm install
```
## First Run
### Start the backend:
```bash
# Debian / Ubuntu
node server.js
// Or in Background
setsid node server.js >> wadboard.log 2>&1 < /dev/null &
```
## Open the frontend in your browser
On first use:
- you will be asked to set an admin password

- the password is stored hashed (SHA-256) in wadph-data.json


## Security Model

Wadboard uses a simple but effective model:

### View Mode (default)
- No authentication required
- All actions are read-only
- Safe to display on internal screens

### Edit Mode (admin)
- Requires admin password
- Enables:
  - create / edit / delete entries
  - reorder cards
  - run SSH and host commands
  - configure battery alerts
  - change admin password

Admin sessions:
- stored in memory
- expire automatically
- bound to browser cookies

There are **no credentials embedded in frontend code**.

## Wake-on-LAN & Power Control

### Basic WOL
- Uses system `wol` binary
- Parameters:
  - MAC address
  - broadcast address
  - UDP port
  - SecureON password (optional)

### MikroTik WOL
- Calls RouterOS scripts via REST API
- Supports SSH actions per task
- Useful for advanced routing / VLAN setups

### WadESP-PowerSW
- ESP8266/ESP32 HTTP relay controller
- Designed to simulate a physical power button
- Uses short relay pulse (100–300 ms)

Example endpoint used by Wadboard:
```http
POST http://<esp-ip>/power/on
```
No authentication headers are required by default
(recommended only for trusted local networks).

## SSH Actions
### SSH actions can be attached to any WOL task:

- executed manually from the UI

- protected by admin password when not in edit mode

## Nginx Reverse Proxy (Optional)

```nginx
server {
    listen 80;
    server_name your.domain.local;

    root /path/to/wadboard/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location ^~ /api/ {
        proxy_pass http://127.0.0.1:4000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```


## Project/Repo Structure <br>

```bash
.
├── LICENSE
├── README.md
├── backend
│   ├── data.json          #<— Wadboard Date Base file, like your custom services, quick links ans etc...
│   ├── package-lock.json  #<— Versions
│   ├── package.json       #<— Versions
│   └── server.js          #<— Main backend file, checking services status, sending WoL and etc...
└── frontend
    └── index.html         #<— Frontend file (css/js included)

3 directories, 7 files
```
