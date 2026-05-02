# Bastión Xólot

A Raspberry Pi–based inline network security gateway paired with a React Native mobile app. Discovers devices on the LAN, detects suspicious behavior using metadata-only monitoring + Suricata IDS, generates plain-English alerts at three audience levels (`grandma` / `standard` / `nerd`), and supports reversible device quarantine.

---

## Repository layout

```
bastion-xolot/
├── backend/           Node.js + TypeScript API, SQLite, WebSocket, AI explanations
├── edge/agent/        Python edge agent (discovery, DNS, anomaly, enforcement)
├── mobile/            React Native app (iOS + Android)
├── infra/
│   ├── scripts/       Pi setup scripts (NAT, firewall, DNS sinkhole, Suricata)
│   └── systemd/       systemd unit files for production
└── shared/            TypeScript types shared between backend and mobile
```

---

## Prerequisites

| Component | Requirement |
|---|---|
| Backend | Node.js ≥ 22.11, npm |
| Edge agent | Python ≥ 3.11, `pip`, `venv` |
| Mobile app | Node.js ≥ 22.11, React Native CLI, Xcode (iOS) or Android Studio (Android) |
| Gateway hardware | Raspberry Pi 4 / 5, microSD, USB-to-Ethernet adapter, Pi power supply |
| AI explanations (optional) | `ANTHROPIC_API_KEY` from console.anthropic.com |

---

## Quick start (development on a single laptop, no Pi)

You can run the **backend + mobile app** locally without any Pi or edge agent. Useful for UI work and demos.

### 1. Clone the repo

```bash
git clone https://github.com/brawndon-manu/bastion-xolot.git
cd bastion-xolot
```

### 2. Configure environment

Create a `.env` file in the repo root:

```env
NODE_ENV=development
API_PORT=3000
MONITOR_ONLY=true
AUTO_QUARANTINE_THRESHOLD=50
AUTH_SECRET=dev-secret-change-me

# Optional — enables AI-generated alert explanations.
# If omitted, the system uses deterministic static fallbacks and remains fully functional.
ANTHROPIC_API_KEY=sk-ant-...
AI_DAILY_CALL_LIMIT=1000
```

### 3. Start the backend

```bash
cd backend
npm install
npm run dev
```

The API is now live at `http://localhost:3000`. Verify with:

```bash
curl http://localhost:3000/health
```

### 4. Start the mobile app

In a new terminal:

```bash
cd mobile
npm install

# iOS (Mac only)
cd ios && pod install && cd ..
npm run ios

# Android
npm run android
```

The app launches in the simulator and connects to the backend over your local network.

---

## Full deployment on a Raspberry Pi (production path)

This is the real appliance setup — Pi sits inline between modem and router.

### 1. Hardware

```
[ Modem ]──eth0──[ Raspberry Pi ]──eth1 (USB)──[ Business Router ]──Wi-Fi──[ LAN devices ]
```

- `eth0` (built-in) → WAN, plugged into the modem
- `eth1` (USB-Ethernet) → LAN, plugged into the router's WAN port

### 2. Flash and boot

Flash Raspberry Pi OS (64-bit) to a microSD. Boot the Pi, log in over SSH:

```bash
ssh pi@<pi-ip>
```

### 3. Clone and run install scripts

```bash
sudo apt update && sudo apt install -y git python3-venv nodejs npm
git clone https://github.com/brawndon-manu/bastion-xolot.git
cd bastion-xolot

sudo bash infra/scripts/configure_interfaces.sh
sudo bash infra/scripts/enable_ip_forwarding.sh
sudo bash infra/scripts/setup_nat.sh
sudo bash infra/scripts/setup_firewall.sh
sudo bash infra/scripts/setup_dns_sinkhole.sh
sudo bash infra/scripts/setup_suricata.sh
```

### 4. Build the backend

```bash
cd backend
npm install
npm run build
```

### 5. Set up the edge agent

```bash
cd ../edge/agent
python3 -m venv ../../venv
source ../../venv/bin/activate
pip install -e .
deactivate
```

### 6. Production `.env`

Place at the repo root (referenced by both systemd units):

```env
NODE_ENV=production
API_PORT=3000
DB_PATH=/var/lib/bastion-xolot/bastion.db
MONITOR_ONLY=false
AUTO_QUARANTINE_THRESHOLD=50
AUTH_SECRET=<generate-a-long-random-string>

ANTHROPIC_API_KEY=sk-ant-...
AI_DAILY_CALL_LIMIT=1000

ALERT_DEDUP_WINDOW_MS=1800000
ANOMALY_RESOLUTION_WINDOW_MS=600000
DESIRED_STATE_PATH=/var/lib/bastion/enforcement/desired_state.json
```

Create the data directory:

```bash
sudo mkdir -p /var/lib/bastion-xolot /var/lib/bastion/enforcement
sudo chown -R bastion:bastion /var/lib/bastion-xolot /var/lib/bastion
```

### 7. Install systemd services

```bash
sudo cp infra/systemd/bastion-api.service /etc/systemd/system/
sudo cp infra/systemd/bastion-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bastion-api.service bastion-agent.service
```

Check status:

```bash
sudo systemctl status bastion-api.service
sudo systemctl status bastion-agent.service
sudo journalctl -u bastion-agent.service -f
```

### 8. Verify

```bash
curl http://<pi-ip>:3000/health
```

Should return `{"status":"ok",...}` with database and websocket reporting healthy.

### 9. Connect the mobile app

Build the mobile app with the Pi's IP as the API host (configure in the app's onboarding flow), pair using the PIN displayed by the gateway, and you're live.

---

## Configuration reference

All configuration is read from `.env`. The full list:

| Variable | Default | Purpose |
|---|---|---|
| `NODE_ENV` | `development` | `production` enables strict checks |
| `API_PORT` | `3000` | HTTP / WebSocket port |
| `DB_PATH` | dev: `backend/data/bastion.db` · prod: `/var/lib/bastion-xolot/bastion.db` | SQLite file |
| `MONITOR_ONLY` | `true` | When true, alerts fire but no firewall changes apply |
| `AUTO_QUARANTINE_THRESHOLD` | `50` | Risk-score threshold for auto-quarantine |
| `AUTH_SECRET` | dev: placeholder · prod: required | HMAC secret for session tokens |
| `ALERT_DEDUP_WINDOW_MS` | `1800000` (30 min) | Repeat-alert dedup window |
| `ANOMALY_RESOLUTION_WINDOW_MS` | `600000` (10 min) | Window to auto-resolve anomalies |
| `DESIRED_STATE_PATH` | `/var/lib/bastion/enforcement/desired_state.json` | Edge agent's enforcement state file |
| `ANTHROPIC_API_KEY` | unset | Enables AI explanations; static fallback used when unset |
| `AI_DAILY_CALL_LIMIT` | `1000` | Daily cap on Claude API calls (0 = disable AI entirely) |

---

## API overview

| Route | Purpose |
|---|---|
| `GET /health` | Service + DB + WebSocket health check |
| `POST /auth/pair` | PIN-based pairing → returns session token |
| `GET /devices` | LAN device inventory |
| `GET /alerts` | Active and historical alerts |
| `POST /events` | Edge agent → backend event ingestion |
| `POST /enforcement/quarantine` | Quarantine a device |
| `POST /enforcement/release` | Release a device from quarantine |
| `GET /enforcement/history` | Audit trail |

WebSocket: same host/port, broadcasts alert / device / enforcement events to connected clients.

---

## Triggering a demo alert

From any host on the LAN, run an Nmap scan to fire the port-scan detector:

```bash
nmap -sS -p 1-1000 192.168.1.0/24
```

Within seconds, the mobile app will receive a high-severity alert. Tap into it to see the explanation rendered in your selected translation level (Settings → Translation Level: `grandma` / `standard` / `nerd`), then quarantine the offending device and watch its connectivity drop.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `curl /health` fails | `sudo systemctl status bastion-api.service`, then `journalctl -u bastion-api.service -n 50` |
| No devices appear | `sudo journalctl -u bastion-agent.service -f` — ensure ARP/DHCP modules see traffic |
| Alerts arrive but no AI text | `ANTHROPIC_API_KEY` unset, daily budget hit, or upstream call failed — system falls back to static text intentionally |
| Quarantine has no effect | Confirm `MONITOR_ONLY=false` and `nft list ruleset` shows the bastion table |
| Mobile app can't connect | App points at the wrong host / port; check Pi LAN IP and that port 3000 is open in `setup_firewall.sh` |

---

## Development scripts

```bash
# Backend
cd backend
npm run dev      # ts-node-dev with hot reload
npm run build    # compile to dist/
npm start        # run compiled output

# Mobile
cd mobile
npm start        # Metro bundler
npm run ios
npm run android

# Edge agent (Pi only — needs raw network access)
source venv/bin/activate
python -m bastion_agent.main
```

---

## License

Academic project — California State University, Fullerton (Spring 2026).
