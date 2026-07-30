# SentryWatch — Network Intrusion Detection System (IDS)

A signature-based Network Intrusion Detection System for small-scale business networks, featuring a real-time web dashboard. Built with **Python (FastAPI + Scapy)** on the backend and **React (Vite)** on the frontend.

---

## Features

### Backend (Python/FastAPI)

- **Packet Capture**: Real-time network traffic capture using Scapy
- **Signature-Based Detection**: Pattern matching against known attack signatures
- **REST API**: Full-featured API for management and monitoring
- **Alert Management**: View, filter, and manage security alerts
- **SQLite Database**: Lightweight, file-based storage
- **Extensible Signatures**: JSON-based signature definitions
- **User Authentication**: JWT-based auth with Argon2 password hashing (register, login, token-protected endpoints)
- **Bounded Packet Queue**: Captured packets are pushed onto a bounded queue and processed in batches by a dedicated writer thread — reduces SQLite lock contention under load
- **UFW Firewall Integration**: Auto-block source IPs on critical alerts, plus manual block/unblock/list via API
- **Comprehensive Test Suite**: 174+ unit and integration tests

### Frontend (React/Vite)

- **Live Dashboard**: Real-time detection status, alert stats, severity breakdown, top source IPs, and most triggered signatures
- **Alert Management**: Paginated, filterable alert list with inline status changes and delete confirmation
- **Signature CRUD**: Full create, read, update, delete, and toggle for detection signatures
- **Detection Engine Control**: Start/stop detection, reload signatures, view system config and network info
- **Configurable Backend URL**: Change the API target at runtime via the System page (no rebuild required)
- **Dark-Themed UI**: Modern, responsive design with animated status indicators
- **Smart Polling**: Auto-polls the backend; pauses when the browser tab is hidden

---

## System Requirements

- **OS**: Ubuntu Linux 20.04 / 22.04 (packet capture tested on Linux)
- **Python**: 3.10+
- **Node.js**: 18+
- **npm**: 9+
- **Root privileges** or `CAP_NET_RAW` capability for packet capture

---

## Quick Start

### 1. Clone & Setup Backend

```bash
# Navigate to the backend directory
cd backend

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Configure Backend

```bash
# Find your network interface
ip link

# Edit configuration
nano .env
```

Update `.env`:

```env
NETWORK_INTERFACE=eth0
# Common names: eth0, ens33, enp0s3, wlan0

# Firewall auto-blocking (requires ufw installed)
UFW_ENABLED=false
AUTO_BLOCK_CRITICAL=true
```

### 3. Initialize Backend Database

```bash
python scripts/load_signatures.py
```

### 4. Run Backend Server

Choose one option for packet-capture permissions:

**Option A: Run with sudo (Development)**

```bash
sudo venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Option B: Set `CAP_NET_RAW` capability (Recommended for production-like usage)**

```bash
# One-time setup
sudo setcap cap_net_raw+ep venv/bin/python3

# Run without sudo
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Option C: Use startup script**

```bash
chmod +x scripts/start_ids.sh
sudo ./scripts/start_ids.sh --dev
```

The API will be available at `http://localhost:8000`.

### 5. Setup Frontend

Open a new terminal:

```bash
# Navigate to the frontend directory
cd frontend

# Install Node.js dependencies
npm install

# Start the development server
npm run dev
```

The web interface will be available at `http://localhost:5173`.

> **Note**: The frontend connects to the backend at `http://localhost:8000` by default. You can change this URL at runtime in the System page of the web UI.

### 6. Authenticate & Start Detection

**Via the Web UI:**

1. Open `http://localhost:5173`
2. The backend auto-seeds a default admin account
3. Use the API directly to login (web UI auth coming soon):

**Via the API:**

```bash
# Login with the default admin account
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Start the detection engine
curl -X POST http://localhost:8000/api/v1/system/detection/start \
  -H "Authorization: Bearer $TOKEN"

# Check status
curl http://localhost:8000/api/v1/system/status \
  -H "Authorization: Bearer $TOKEN"
```

> **Default credentials**: `admin` / `admin123` (seeded automatically on first backend startup)

---

## Accessing the Application

| Interface              | URL                         | Description                   |
| ---------------------- | --------------------------- | ----------------------------- |
| **Web UI**             | http://localhost:5173       | SentryWatch IDS Console       |
| **API Docs (Swagger)** | http://localhost:8000/docs  | Interactive API documentation |
| **API Docs (ReDoc)**   | http://localhost:8000/redoc | Alternative API docs          |
| **API Health**         | http://localhost:8000/ping  | Simple health check           |

---

## Project Structure

```
ids-project/
├── backend/                      # Python/FastAPI backend
│   ├── app/
│   │   ├── main.py               # FastAPI application entry
│   │   ├── core/                 # Configuration, logging, and auth
│   │   │   ├── config.py         # Pydantic settings
│   │   │   ├── logging.py        # Loguru setup
│   │   │   └── auth.py           # JWT + Argon2 password hashing
│   │   ├── database/             # SQLAlchemy setup
│   │   ├── models/               # Database models (includes User)
│   │   ├── schemas/              # Pydantic schemas
│   │   ├── services/             # Business logic
│   │   │   ├── sniffer.py        # Packet capture
│   │   │   ├── parser.py         # Packet parsing
│   │   │   ├── matcher.py        # Signature matching
│   │   │   ├── detector.py       # Detection engine
│   │   │   ├── alert_manager.py  # Alert CRUD and aggregation
│   │   │   └── firewall.py       # UFW block/unblock/list
│   │   ├── api/                  # REST API routes
│   │   │   ├── deps.py           # FastAPI DI container
│   │   │   ├── auth_deps.py      # Auth dependency
│   │   │   └── routes/           # Endpoint definitions
│   │       ├── alerts.py     # Alert endpoints
│   │       ├── signatures.py # Signature endpoints
│   │       ├── system.py     # System control endpoints
│   │       ├── auth.py       # Authentication endpoints
│   │       └── firewall.py   # Firewall block/unblock endpoints
│   │   ├── signatures/           # JSON signature files
│   │   └── workers/              # Background workers
│   ├── data/                     # Database and logs
│   ├── scripts/                  # Utility scripts
│   ├── tests/                    # 174+ unit and integration tests
│   ├── requirements.txt
│   └── .env
│
├── frontend/                     # React/Vite web UI
│   ├── src/
│   │   ├── main.jsx              # React entry point
│   │   ├── App.jsx               # Router and layout
│   │   ├── api/                  # Backend API client
│   │   │   ├── client.js         # Fetch wrapper (configurable base URL)
│   │   │   ├── alerts.js         # Alert API calls
│   │   │   ├── signatures.js     # Signature API calls
│   │   │   ├── system.js         # System API calls
│   │   │   └── format.js         # Formatting helpers
│   │   ├── pages/                # Route pages
│   │   │   ├── Dashboard.jsx     # Live stats and overview
│   │   │   ├── Alerts.jsx        # Paginated alert list
│   │   │   ├── AlertDetail.jsx   # Single alert view
│   │   │   ├── Signatures.jsx    # Signature CRUD
│   │   │   └── SystemPage.jsx    # Engine control and config
│   │   ├── components/           # Reusable UI components
│   │   │   ├── NavRail.jsx       # Sidebar navigation
│   │   │   ├── PulseStrip.jsx    # Animated status indicator
│   │   │   ├── ConnectionBanner.jsx
│   │   │   ├── Panel.jsx         # Card container
│   │   │   ├── Modal.jsx         # Overlay dialog
│   │   │   ├── SignatureForm.jsx # Signature editor form
│   │   │   ├── SeverityBadge.jsx
│   │   │   ├── StatusBadge.jsx
│   │   │   ├── StatTile.jsx
│   │   │   └── EmptyState.jsx
│   │   ├── hooks/
│   │   │   └── usePolling.js     # Auto-polling with tab visibility
│   │   └── styles/
│   │       ├── tokens.css        # Design tokens (dark theme)
│   │       └── components.css    # Component styles
│   ├── public/
│   │   ├── favicon.svg
│   │   └── icons.svg
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
│
├── README.md
```

---

## Web UI Pages

| Page             | Route         | Description                                                                                                            |
| ---------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **Dashboard**    | `/`           | Live detection status, alert stats, severity bar chart, top source IPs, most triggered signatures, recent alerts       |
| **Alerts**       | `/alerts`     | Paginated alert table with severity/status/source IP filters, inline status change, and delete                         |
| **Alert Detail** | `/alerts/:id` | Full alert details, payload snippet, connection info, signature info, status change                                    |
| **Signatures**   | `/signatures` | Signature CRUD table with enable/disable toggle, edit modal, create modal, category/severity filters                   |
| **System**       | `/system`     | Detection engine start/stop, reload signatures, network info, config display, alert cleanup, backend URL configuration |

The UI polls the backend at configurable intervals (dashboards polls every 4–5s). Polling pauses automatically when the browser tab is hidden.

---

## Backend API Endpoints

> All endpoints under `/api/v1/*` (except `/auth/register` and `/auth/login`) require a JWT Bearer token in the `Authorization` header.

### Authentication (Public)

| Method | Endpoint                | Description              |
| ------ | ----------------------- | ------------------------ |
| POST   | `/api/v1/auth/register` | Create a new user        |
| POST   | `/api/v1/auth/login`    | Login, get JWT token     |
| GET    | `/api/v1/auth/me`       | Get current user details |

### System Control

| Method | Endpoint                           | Description        |
| ------ | ---------------------------------- | ------------------ |
| GET    | `/api/v1/system/health`            | Health check       |
| GET    | `/api/v1/system/status`            | System status      |
| GET    | `/api/v1/system/network`           | Network interfaces |
| GET    | `/api/v1/system/config`            | Current config     |
| POST   | `/api/v1/system/detection/start`   | Start detection    |
| POST   | `/api/v1/system/detection/stop`    | Stop detection     |
| POST   | `/api/v1/system/signatures/reload` | Reload signatures  |

### Alerts

| Method | Endpoint                     | Description                     |
| ------ | ---------------------------- | ------------------------------- |
| GET    | `/api/v1/alerts`             | List alerts (paginated)         |
| GET    | `/api/v1/alerts/{id}`        | Get alert details               |
| PATCH  | `/api/v1/alerts/{id}/status` | Update alert status             |
| DELETE | `/api/v1/alerts/{id}`        | Delete alert                    |
| GET    | `/api/v1/alerts/stats`       | Alert statistics                |
| POST   | `/api/v1/alerts/cleanup`     | Delete alerts older than N days |

### Signatures

| Method | Endpoint                         | Description               |
| ------ | -------------------------------- | ------------------------- |
| GET    | `/api/v1/signatures`             | List signatures           |
| POST   | `/api/v1/signatures`             | Create signature          |
| GET    | `/api/v1/signatures/{id}`        | Get signature             |
| PUT    | `/api/v1/signatures/{id}`        | Update signature          |
| DELETE | `/api/v1/signatures/{id}`        | Delete signature          |
| POST   | `/api/v1/signatures/{id}/toggle` | Toggle enabled            |
| GET    | `/api/v1/signatures/categories`  | List signature categories |

### Firewall

| Method | Endpoint                            | Description                         |
| ------ | ----------------------------------- | ----------------------------------- |
| POST   | `/api/v1/firewall/block`            | Block an IP via ufw + DB record     |
| DELETE | `/api/v1/firewall/unblock/{ip}`     | Remove a ufw deny rule for an IP    |
| GET    | `/api/v1/firewall/blocked`          | List all currently blocked IPs      |

The firewall endpoints require a JWT Bearer token. On critical-severity alerts, the detection engine automatically calls `POST /api/v1/firewall/block` if `AUTO_BLOCK_CRITICAL=true`. The actual ufw command is only executed when `UFW_ENABLED=true`.

---

## Usage Examples

> **Note**: All API endpoints (except `/`, `/ping`, `/auth/register`, `/auth/login`) require a JWT Bearer token in the `Authorization` header.

### Authentication

```bash
# Register a new user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "securepass123"}'

# Login and capture the token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Check your auth status
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### Start Detection

```bash
curl -X POST http://localhost:8000/api/v1/system/detection/start \
  -H "Authorization: Bearer $TOKEN"

# Check status
curl http://localhost:8000/api/v1/system/status \
  -H "Authorization: Bearer $TOKEN"
```

### View Alerts

```bash
# Get all alerts
curl http://localhost:8000/api/v1/alerts \
  -H "Authorization: Bearer $TOKEN"

# Filter by severity
curl "http://localhost:8000/api/v1/alerts?severity=critical" \
  -H "Authorization: Bearer $TOKEN"

# Get alert statistics
curl http://localhost:8000/api/v1/alerts/stats \
  -H "Authorization: Bearer $TOKEN"
```

### Manage Signatures

```bash
# Create a new signature
curl -X POST http://localhost:8000/api/v1/signatures \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Custom SSH Alert",
    "description": "Detect SSH connections",
    "protocol": "tcp",
    "dest_port": "22",
    "severity": "medium",
    "category": "monitoring"
  }'

# Toggle signature on/off
curl -X POST http://localhost:8000/api/v1/signatures/1/toggle \
  -H "Authorization: Bearer $TOKEN"
```

### Firewall Management

```bash
# Block an IP address (adds ufw deny rule + database record)
curl -X POST http://localhost:8000/api/v1/firewall/block \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ip_address": "192.168.1.100", "reason": "Suspicious activity"}'

# Remove a block
curl -X DELETE http://localhost:8000/api/v1/firewall/unblock/192.168.1.100 \
  -H "Authorization: Bearer $TOKEN"

# List all blocked IPs
curl http://localhost:8000/api/v1/firewall/blocked \
  -H "Authorization: Bearer $TOKEN"
```

### Auto-Blocking

When `AUTO_BLOCK_CRITICAL=true` (default), any packet that triggers a **critical**-severity signature automatically records the source IP in the `blocked_ips` table. If `UFW_ENABLED=true` is also set, a `ufw deny from <ip>` command is executed on the host system as well.

### Adding Custom Signatures

Edit `app/signatures/custom.json` and then reload:

```bash
curl -X POST http://localhost:8000/api/v1/system/signatures/reload \
  -H "Authorization: Bearer $TOKEN"
```

---

## Running Tests

### Backend Tests (174+ tests)

```bash
cd backend
source venv/bin/activate
pytest tests/ -v

# Run a specific test file
pytest tests/test_utils/test_ip_utils.py -v

# Run with coverage report
pip install pytest-cov
pytest tests/ --cov=app --cov-report=term-missing
```

**Backend test layout:**

| Directory              | Contents                                                                            |
| ---------------------- | ----------------------------------------------------------------------------------- |
| `tests/test_utils/`    | IP validation, CIDR matching, regex compilation & matching                          |
| `tests/test_services/` | Signature matcher (protocol/port/payload), alert manager (CRUD, aggregation, stats), firewall (UFW subprocess wrapper) |
| `tests/test_api/`      | System control, alert CRUD, signature CRUD, firewall block/unblock/list — all via TestClient |

Tests use an in-memory SQLite database with per-test transaction rollback. The detection engine and permission checks are mocked so root access is never required.

### Frontend Tests

```bash
cd frontend
npm run lint   # Run Oxlint (React linting)
```

---

## Permissions for Packet Capture

Run the server with elevated privileges or grant the `CAP_NET_RAW` capability to the Python interpreter:

```bash
# One-time: set capability on the venv Python
sudo setcap cap_net_raw+ep venv/bin/python3

# Development (quick): run with sudo
sudo venv/bin/uvicorn app.main:app --reload
```

---

## Testing with Kali Linux

From an attacker machine (e.g., Kali Linux):

```bash
# Port scan (will trigger TCP SYN Scan Detection)
nmap -sS <target_ip>

# Ping sweep (will trigger ICMP Ping Sweep)
ping <target_ip>

# SQL Injection attempt (will trigger SQL Injection Attempt)
curl "http://<target_ip>:8080/?id=1' OR '1'='1'"
```

---

## Troubleshooting

- **"Permission denied" on packet capture**: ensure `CAP_NET_RAW` is set or run with `sudo`.
- **No alerts generated**: check the System page in the web UI (or `GET /api/v1/system/status`), verify signatures are loaded (`GET /api/v1/signatures`), confirm the `.env` interface is correct, and ensure traffic flows through the monitored interface.
- **Frontend shows "Backend unreachable"**: ensure the backend server is running on port 8000, or update the API URL in the System page of the web UI.
- **Database errors**: remove `data/ids.db` and re-run `python scripts/load_signatures.py`.
