# Network Intrusion Detection System (IDS) Backend

A signature-based Network Intrusion Detection System designed for small-scale business networks. Built with Python, FastAPI, and Scapy. This repository supports Ubuntu (Linux) systems only.

## Features

- **Packet Capture**: Real-time network traffic capture using Scapy
- **Signature-Based Detection**: Pattern matching against known attack signatures
- **REST API**: Full-featured API for management and monitoring
- **Alert Management**: View, filter, and manage security alerts
- **SQLite Database**: Lightweight, file-based storage
- **Extensible Signatures**: JSON-based signature definitions
- **Dependency Injection**: Services wired through FastAPI DI — no global singletons, mock-friendly for testing
- **Async Control Endpoints**: Detection start/stop/reload are async FastAPI handlers — DB I/O offloaded to a thread pool, event loop stays free
- **Bounded Packet Queue**: Captured packets are pushed onto a bounded queue and processed in batches by a dedicated writer thread — reduces SQLite lock contention under load
- **Comprehensive Test Suite**: 148 unit + integration tests covering utilities, services, and all API endpoints

## Supported Platforms

- Ubuntu Linux (tested on Ubuntu 20.04 / 22.04)

## Requirements

- Python 3.10+
- Root privileges or `CAP_NET_RAW` capability for packet capture

---

## Quick Start - Ubuntu/Linux

### 1. Setup Environment

```bash
cd ids-backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

```bash
# Find your network interface
ip link
# or
ip addr

# Edit configuration
nano .env
```

Update `.env`:

```env
NETWORK_INTERFACE=eth0
# Common names: eth0, ens33, enp0s3, wlan0
```

### 3. Initialize Database

```bash
python scripts/load_signatures.py
```

### 4. Run the Server

There are two common options to provide packet-capture permissions:

**Option A: Run with sudo (Development)**

```bash
sudo venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Option B: Set `CAP_NET_RAW` capability (Recommended for production-like usage)**

```bash
# One-time setup (set capability on the venv Python)
sudo setcap cap_net_raw+ep venv/bin/python3

# Run without sudo
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Option C: Use startup script**

```bash
chmod +x scripts/start_ids.sh
sudo ./scripts/start_ids.sh --dev
```

### 5. Start Detection

```bash
# Start detection engine
curl -X POST http://localhost:8000/api/v1/system/detection/start

# Check status
curl http://localhost:8000/api/v1/system/status
```

---

## Access the API

- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/ping

## API Endpoints

### System Control

| Method | Endpoint                           | Description          |
| ------ | ---------------------------------- | -------------------- |
| GET    | `/api/v1/system/health`            | Health check         |
| GET    | `/api/v1/system/status`            | System status        |
| GET    | `/api/v1/system/network`           | Network interfaces   |
| GET    | `/api/v1/system/config`            | Current config       |
| POST   | `/api/v1/system/detection/start`   | Start detection      |
| POST   | `/api/v1/system/detection/stop`    | Stop detection       |
| POST   | `/api/v1/system/signatures/reload` | Reload signatures    |

### Alerts

| Method | Endpoint                     | Description                 |
| ------ | ---------------------------- | --------------------------- |
| GET    | `/api/v1/alerts`             | List alerts (paginated)     |
| GET    | `/api/v1/alerts/{id}`        | Get alert details           |
| PATCH  | `/api/v1/alerts/{id}/status` | Update alert status         |
| DELETE | `/api/v1/alerts/{id}`        | Delete alert                |
| GET    | `/api/v1/alerts/stats`       | Alert statistics            |
| POST   | `/api/v1/alerts/cleanup`     | Delete alerts older than N days |

### Signatures

| Method | Endpoint                         | Description             |
| ------ | -------------------------------- | ----------------------- |
| GET    | `/api/v1/signatures`             | List signatures         |
| POST   | `/api/v1/signatures`             | Create signature        |
| GET    | `/api/v1/signatures/{id}`        | Get signature           |
| PUT    | `/api/v1/signatures/{id}`        | Update signature        |
| DELETE | `/api/v1/signatures/{id}`        | Delete signature        |
| POST   | `/api/v1/signatures/{id}/toggle` | Toggle enabled          |
| GET    | `/api/v1/signatures/categories`  | List signature categories |

## Usage Examples

### Start Detection

```bash
# Start the detection engine
curl -X POST http://localhost:8000/api/v1/system/detection/start

# Check status
curl http://localhost:8000/api/v1/system/status
```

### View Alerts

```bash
# Get all alerts
curl http://localhost:8000/api/v1/alerts

# Filter by severity
curl "http://localhost:8000/api/v1/alerts?severity=critical"

# Get alert statistics
curl http://localhost:8000/api/v1/alerts/stats
```

### Manage Signatures

```bash
# Create a new signature
curl -X POST http://localhost:8000/api/v1/signatures \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom SSH Alert",
    "description": "Detect SSH connections",
    "protocol": "tcp",
    "dest_port": "22",
    "severity": "medium",
    "category": "monitoring"
  }'

# Toggle signature on/off
curl -X POST http://localhost:8000/api/v1/signatures/1/toggle
```

## Project Structure

```
ids-backend/
├── app/
│   ├── main.py              # FastAPI application entry
│   ├── core/                # Configuration and logging
│   ├── database/            # SQLAlchemy setup
│   ├── models/              # Database models
│   ├── schemas/             # Pydantic schemas
│   ├── services/            # Business logic (no global singletons)
│   │   ├── sniffer.py       # Packet capture
│   │   ├── parser.py        # Packet parsing
│   │   ├── matcher.py       # Signature matching
│   │   ├── detector.py      # Detection engine (bounded packet queue + batch writer thread)
│   │   └── alert_manager.py # Alert handling
│   ├── api/                 # REST API routes
│   │   ├── deps.py          # FastAPI DI container
│   │   └── routes/          # Endpoint definitions
│   ├── signatures/          # JSON signature files
│   └── workers/             # Background workers
├── data/                    # Database and logs
├── scripts/                 # Utility scripts
├── tests/                   # 148 unit + integration tests
│   ├── test_utils/          # IP & regex utility tests
│   ├── test_services/       # Matcher & alert manager tests
│   └── test_api/            # System, alert & signature endpoint tests
├── requirements.txt
├── .env
└── README.md
```

## Adding Custom Signatures

Edit `app/signatures/custom.json` and then reload:

```bash
curl -X POST http://localhost:8000/api/v1/system/signatures/reload
```

## Permissions for Packet Capture

Run the server with elevated privileges or grant the `CAP_NET_RAW` capability to the Python interpreter used by the virtual environment.

```bash
# One-time: set capability on the venv Python
sudo setcap cap_net_raw+ep venv/bin/python3

# Development (quick): run with sudo
sudo venv/bin/uvicorn app.main:app --reload
```

## Running Tests

The project includes **148 tests** covering utilities, services, and all API endpoints.

```bash
# Run the full suite from the project root
pytest tests/ -v

# Run a specific test file
pytest tests/test_utils/test_ip_utils.py -v

# Run with coverage report
pip install pytest-cov
pytest tests/ --cov=app --cov-report=term-missing
```

**Test layout:**

| Directory | Contents |
|-----------|----------|
| `tests/test_utils/` | IP validation, CIDR matching, regex compilation & matching |
| `tests/test_services/` | Signature matcher (protocol/port/payload), alert manager (CRUD, aggregation, stats) |
| `tests/test_api/` | System control, alert CRUD, signature CRUD — all via TestClient |

Tests use an in-memory SQLite database with per-test transaction rollback for full isolation. The detection engine and permission checks are mocked so root access is never required.

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

## Troubleshooting (Ubuntu)

- "Permission denied" on packet capture: ensure `CAP_NET_RAW` is set or run with `sudo`.
- No alerts generated: check `GET /api/v1/system/status`, verify signatures with `GET /api/v1/signatures`, confirm `.env` interface, and ensure traffic flows through the monitored interface.
- Database errors: remove `data/ids.db` and re-run `python scripts/load_signatures.py`.

## License

MIT License - See LICENSE file for details.

## Author

Final Year Project - Network Intrusion Detection System
