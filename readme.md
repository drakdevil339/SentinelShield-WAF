# SentinelShield

**Advanced Intrusion Detection & Web Protection System**

A lightweight Web Application Firewall (WAF) and Intrusion Detection System (IDS) built in Python. SentinelShield inspects incoming HTTP requests, detects malicious payloads, monitors abusive traffic, generates alerts, and provides a real-time analytics dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Starting the Server](#starting-the-server)
  - [Testing with PowerShell (Windows)](#testing-with-powershell-windows)
  - [Testing with curl](#testing-with-curl)
  - [Dashboard](#dashboard)
  - [API Endpoints](#api-endpoints)
  - [Log Files](#log-files)
- [Attack Detection Categories](#attack-detection-categories)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Student Practical Work](#student-practical-work)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

SentinelShield simulates a realistic Intrusion Detection and Web Protection System. It helps cybersecurity students and professionals understand how:

- Web Application Firewalls detect threats using pattern matching and signature-based rules
- HTTP requests are inspected for malicious intent
- Rate limiting and behavior analysis prevent brute-force and flooding attacks
- Security events are logged, categorized, and visualized on dashboards

---

## Features

| Feature | Description |
|---------|-------------|
| **Rule-Based Detection Engine** | 22+ detection rules across 7 attack categories with severity scoring |
| **SQL Injection Detection** | Union-based, tautology, time-based, blind, hex-encoded payloads |
| **Cross-Site Scripting (XSS) Detection** | Script tags, event handlers, javascript protocol, encoded variants |
| **LFI/RFI Detection** | Directory traversal, sensitive file access, remote file inclusion |
| **Command Injection Detection** | Shell commands, chaining operators, reverse shell indicators |
| **SSRF Detection** | Internal IP scanning, cloud metadata endpoints |
| **Suspicious User-Agent Detection** | Identifies scanner tools (sqlmap, nikto, burp, etc.) |
| **Rate Limiting** | Sliding window algorithm with automatic IP banning |
| **Real-Time Dashboard** | Interactive HTML dashboard with Charts.js visualizations |
| **JSON & Plain Text Logging** | Structured and human-readable log formats |
| **Access Logs** | Standard Apache-combined format logging |
| **REST API Endpoints** | Programmatic access to events and summaries |

---

## Architecture

```
                        CLIENTS / ATTACKERS
                     (curl, browser, scanners)
                              |
                              | HTTP Requests
                              v
                     +------------------+
                     | REQUEST PROCESSOR |
                     | (URL, Params,     |
                     |  Headers, Body)   |
                     +--------+---------+
                              |
               +--------------+--------------+
               |                             |
               v                             v
      +------------------+         +------------------+
      | RULE ENGINE      |         | RATE LIMITER     |
      | SQLi | XSS | LFI |         | Sliding Window   |
      | CMD  | SSRF| UA  |         | IP Tracking      |
      +--------+---------+         +--------+---------+
               |                             |
               +--------------+--------------+
                              |
                              v
                     +------------------+
                     | DECISION ENGINE  |
                     | Block / Allow    |
                     | Log / Alert      |
                     +--------+---------+
                              |
               +--------------+--------------+
               |                             |
               v                             v
      +------------------+         +------------------+
      | LOGGING SYSTEM   |         | DASHBOARD        |
      | JSON + Text Logs |         | Charts + Tables  |
      | Access Logs      |         | Real-time Stats  |
      +------------------+         +------------------+
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- No external dependencies required (uses only Python standard library)
- PowerShell (Windows) or bash (Linux/macOS) for testing

### Setup

Clone or download the project:

```bash
git clone https://github.com/yourusername/sentinel-shield.git
cd sentinel-shield
```

No package installation needed. Just run:

```bash
python sentinel_shield.py
```

---

## Quick Start

### 1. Start the Server

```bash
python sentinel_shield.py
```

You'll see:

```
=============================================================================
|            SentinelShield is ACTIVE                                        |
=============================================================================
|  Dashboard:    http://localhost:8080/                                      |
|  API Events:   http://localhost:8080/api/events                           |
|  API Summary:  http://localhost:8080/api/summary                          |
|  Logs:         http://localhost:8080/logs/                                 |
=============================================================================
|  Rules Loaded: 22                                                          |
|  Rate Limit:   100 req/60s window                                         |
|  Ban Duration: 300s                                                       |
=============================================================================
```

### 2. Test Normal Traffic

```bash
curl http://localhost:8080/
curl "http://localhost:8080/search?q=hello"
```

### 3. Test Attack Detection

```bash
# SQL Injection
curl "http://localhost:8080/login?username=admin' OR '1'='1&password=test"

# XSS
curl "http://localhost:8080/comment?msg=<script>alert(1)</script>"

# Directory Traversal
curl "http://localhost:8080/file?path=../../../etc/passwd"

# Command Injection
curl "http://localhost:8080/ping?host=8.8.8.8|whoami"
```

### 4. Open Dashboard

Navigate to **http://localhost:8080/** in your browser.

---

## Usage Guide

### Starting the Server

```bash
python sentinel_shield.py
```

The server runs on `http://localhost:8080` by default. Press `Ctrl+C` to stop.

### Testing with PowerShell (Windows)

#### Normal Requests

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/search?q=hello" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/submit" -Method POST -Body "name=John&age=30" | Select-Object StatusCode
```

#### SQL Injection

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/login?username=admin' OR '1'='1&password=test" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/products?id=1 UNION SELECT * FROM users" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/user?id=1--" | Select-Object StatusCode
```

#### XSS

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/comment?msg=<script>alert(1)</script>" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/profile?img=x onerror=alert(1)" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/link?url=javascript:alert(1)" | Select-Object StatusCode
```

#### Directory Traversal

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/file?path=../../../etc/passwd" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/read?path=..\..\windows\system32\drivers\etc\hosts" | Select-Object StatusCode
```

#### Command Injection

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/ping?host=8.8.8.8|whoami" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/dns?domain=google.com;ls" | Select-Object StatusCode
```

#### Rate Limiting

```powershell
1..120 | ForEach-Object {
    $result = Invoke-WebRequest -Uri "http://localhost:8080/login?attempt=$_" -UseBasicParsing
    Write-Host "Request $_ : HTTP $($result.StatusCode)"
    if ($result.StatusCode -eq 429) {
        Write-Host "Rate limited at request #$_!" -ForegroundColor Red
        break
    }
}
```

#### Suspicious User-Agent

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/scan" -UserAgent "sqlmap/1.7.2" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/test" -UserAgent "Nikto/2.5.0" | Select-Object StatusCode
```

#### SSRF

```powershell
Invoke-WebRequest -Uri "http://localhost:8080/fetch?url=http://127.0.0.1/admin" | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:8080/curl?url=http://169.254.169.254/latest/meta-data/" | Select-Object StatusCode
```

### Testing with curl

```bash
# Normal
curl http://localhost:8080/

# SQL Injection
curl "http://localhost:8080/login?username=admin' OR '1'='1&password=test"

# XSS
curl "http://localhost:8080/comment?msg=<script>alert(1)</script>"

# LFI
curl "http://localhost:8080/file?path=../../../etc/passwd"

# Command Injection
curl "http://localhost:8080/ping?host=8.8.8.8|whoami"

# Suspicious User-Agent
curl -A "sqlmap/1.7.2" "http://localhost:8080/scan"

# Rate Limiting
for i in $(seq 1 120); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/login?attempt=$i")
  echo "Request $i: HTTP $STATUS"
  if [ "$STATUS" = "429" ]; then echo "Rate limited!"; break; fi
done
```

### Dashboard

Open **http://localhost:8080/** in your browser to see:

| Component | Description |
|-----------|-------------|
| **Stats Cards** | Real-time counters for total events, blocked, monitored, active IPs, banned IPs |
| **Event Timeline** | Line chart showing event frequency over the last 10 minutes |
| **Attack Categories** | Doughnut chart showing distribution by attack type |
| **Recent Events Table** | Scrollable table with IP, method, path, status, severity, category, rule, timestamp |
| **Top IPs** | Most active source IP addresses with request counts |
| **Severity Distribution** | Breakdown of events by severity score |

The dashboard auto-refreshes every 5 seconds.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard (HTML) |
| `/dashboard` | GET | Dashboard (HTML) |
| `/api/events` | GET | Recent security events (JSON) |
| `/api/summary` | GET | Summary statistics (JSON) |
| `/logs/` | GET | List of log files |
| `/logs/sentinel_shield.log` | GET | Plain text event log |
| `/logs/events.json` | GET | JSON event log |
| `/logs/access.log` | GET | HTTP access log |

### Log Files

All logs are stored in the `logs/` directory:

| File | Format | Description |
|------|--------|-------------|
| `sentinel_shield.log` | Plain text | Human-readable event log with timestamps, IPs, status, category, severity |
| `events.json` | JSON | Structured event log suitable for programmatic analysis |
| `access.log` | Apache combined | Standard HTTP access log format |

#### Sample Log Entry (text)

```
[2026-06-19 14:23:45] IP: 127.0.0.1      Status: blocked    Category: SQL Injection     Rule: SQLI-001  Severity: 90  Method: GET   Path: /login
```

#### Sample Log Entry (JSON)

```json
{
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/login?username=admin' OR '1'='1",
  "status": "blocked",
  "rule_id": "SQLI-002",
  "category": "SQL Injection",
  "severity": 85,
  "timestamp": "2026-06-19T14:23:45.123456"
}
```

---

## Attack Detection Categories

| Category | Rule IDs | Example Payload | Severity |
|----------|----------|-----------------|----------|
| **SQL Injection** | SQLI-001 to SQLI-006 | `' OR '1'='1` | 75-95 |
| **XSS** | XSS-001 to XSS-004 | `<script>alert(1)</script>` | 75-90 |
| **LFI/RFI** | LFI-001 to LFI-003 | `../../../etc/passwd` | 85-95 |
| **Command Injection** | CMD-001 to CMD-003 | `\| whoami` | 90-100 |
| **Path Traversal** | PATH-001 | `%00` | 80 |
| **SSRF** | SSRF-001 | `http://169.254.169.254/` | 85 |
| **HTTP Method Abuse** | HTTP-001 | `PUT`, `DELETE` | 50 |
| **Reconnaissance** | UA-001 | sqlmap User-Agent | 40 |

### Severity Thresholds

| Score | Action |
|-------|--------|
| 0-19 | Allowed (no action) |
| 20-49 | Monitored (logged, request allowed) |
| 50-100 | Blocked (HTTP 403) |
| Rate limit | Blocked (HTTP 429) |

---

## Configuration

Edit the `Config` class in `sentinel_shield.py` to customize:

```python
class Config:
    HOST = "0.0.0.0"                 # Server bind address
    PORT = 8080                       # Server port
    RATE_LIMIT_ENABLED = True         # Enable/disable rate limiting
    MAX_REQUESTS_PER_WINDOW = 100     # Max requests per time window
    RATE_WINDOW_SECONDS = 60          # Time window in seconds
    BAN_DURATION_SECONDS = 300        # IP ban duration in seconds
    SEVERITY_THRESHOLD_BLOCK = 50     # Score threshold to block
    SEVERITY_THRESHOLD_WARN = 20      # Score threshold to warn/monitor
    DASHBOARD_REFRESH_SECONDS = 5     # Dashboard auto-refresh interval
```

---

## Project Structure

```
sentinel-shield/
├── sentinel_shield.py      # Main application (WAF engine, server, dashboard)
├── test_attacks.sh         # Automated attack simulation script (Linux/macOS)
├── test_windows.ps1        # Automated attack simulation script (Windows)
├── practical_guide.md      # Student practical work documentation
├── README.md               # This file
├── logs/                   # Auto-generated log directory
│   ├── sentinel_shield.log # Plain text event logs
│   ├── events.json         # JSON structured event logs
│   └── access.log          # HTTP access logs
└── dashboard/              # Auto-generated dashboard directory
    └── index.html          # Interactive HTML dashboard
```

---

## Student Practical Work

This project is designed for cybersecurity education. Students should:

1. **Understand the architecture** - Review how components interact
2. **Review rule definitions** - Examine attack signatures and scoring
3. **Simulate attacks** - Use curl/PowerShell to send normal and malicious requests
4. **Observe detection** - Compare how the system responds to different payloads
5. **Analyze logs** - Examine log files for patterns and suspicious activity
6. **Document findings** - Create a practical journal and final report

### Deliverables

| Component | Description |
|-----------|-------------|
| **Practical Journal** | Step-by-step execution with observations, screenshots, and log interpretation |
| **Final Report** | Summary of attacks performed, detection accuracy, false positives/negatives, recommendations |

See `practical_guide.md` for detailed student instructions.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Dashboard not showing** | Ensure `dashboard/` directory exists. Delete it and restart the server. |
| **`'charmap' codec can't encode character`** | Use the Windows-compatible version (emoji-free). All file writes use `encoding='utf-8'`. |
| **`cannot access local variable 'html'`** | Rename the `html` variable in `_build_html()` to `dashboard_html` or similar. |
| **Port 8080 in use** | Change `Config.PORT` to another value (e.g., 9090). |
| **Rate limit too aggressive** | Increase `MAX_REQUESTS_PER_WINDOW` in Config. |
| **False negatives (attacks not detected)** | Add more patterns to the `_load_rules()` method. |
| **Dashboard not updating** | The background updater thread refreshes every 5 seconds. Refresh your browser manually. |
| **PowerShell execution blocked** | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` before running scripts. |

---

## The Complete Python Code (`sentinel_shield.py`)

Below is the full, working Python code. Copy this into a file named `sentinel_shield.py` and run it:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SentinelShield: Advanced Intrusion Detection & Web Protection System
Windows-Compatible Version - No emojis, UTF-8 safe
"""

import os
import re
import json
import time
import html as html_module
import socket
import hashlib
import datetime
import threading
import http.server
import urllib.parse
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, deque
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

class Config:
    HOST = "0.0.0.0"
    PORT = 8080
    RATE_LIMIT_ENABLED = True
    MAX_REQUESTS_PER_WINDOW = 100
    RATE_WINDOW_SECONDS = 60
    BAN_DURATION_SECONDS = 300
    LOG_DIR = "logs"
    LOG_FILE = os.path.join(LOG_DIR, "sentinel_shield.log")
    JSON_LOG_FILE = os.path.join(LOG_DIR, "events.json")
    ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
    DASHBOARD_DIR = "dashboard"
    DASHBOARD_FILE = os.path.join(DASHBOARD_DIR, "index.html")
    DASHBOARD_REFRESH_SECONDS = 5
    SEVERITY_THRESHOLD_BLOCK = 50
    SEVERITY_THRESHOLD_WARN = 20
    
    @classmethod
    def ensure_dirs(cls):
        for d in [cls.LOG_DIR, cls.DASHBOARD_DIR]:
            os.makedirs(d, exist_ok=True)


# ============================================================
# RULE ENGINE
# ============================================================

class RuleEngine:
    def __init__(self):
        self.rules = self._load_rules()
        self.compiled_rules = self._compile_rules()
    
    def _load_rules(self) -> List[Dict]:
        return [
            # SQL Injection
            {
                "id": "SQLI-001", "name": "Union-Based SQL Injection",
                "category": "SQL Injection", "severity": 90,
                "patterns": [
                    r"(bUNIONbbs+bALLbb+bSELECTb)",
                    r"(bUNIONbbs+bSELECTb)",
                    r"(bUNIONbbs+.*bSELECTb)",
                ],
                "description": "Detects UNION SELECT SQL injection attempts",
                "target": ["params", "body", "url"]
            },
            {
                "id": "SQLI-002", "name": "Classic SQL Injection Markers",
                "category": "SQL Injection", "severity": 85,
                "patterns": [
                    r"('|")s*(OR|AND)s+['"]?s*['"]?",
                    r"(bORb|bANDb)s+1s*=s*1",
                    r"(bORb|bANDb)s+1s*=s*0",
                    r"(bORb|bANDb)s+'1's*=s*'1'",
                    r"(bORb|bANDb)s+"1"s*=s*"1"",
                ],
                "description": "Detects classic OR 1=1 and tautology-based SQLi",
                "target": ["params", "body", "url"]
            },
            {
                "id": "SQLI-003", "name": "SQL Comment Injection",
                "category": "SQL Injection", "severity": 75,
                "patterns": [r"--s*$", r"#s*$", r"/*.**/"],
                "description": "Detects SQL comment injection attempts",
                "target": ["params", "body"]
            },
            {
                "id": "SQLI-004", "name": "SQL Command Execution",
                "category": "SQL Injection", "severity": 95,
                "patterns": [
                    r"(bEXECb|bEXECUTEb)", r"(bxp_cmdshellb)",
                    r"(bINTOs+OUTFILEb)", r"(bINTOs+DUMPFILEb)",
                    r"(bLOAD_FILEb)", r"(bWAITFORs+DELAYb)",
                    r"(bSLEEPbs*(s*d+s*))", r"(bBENCHMARKbs*()",
                ],
                "description": "Detects SQL command execution and time-based blind injection",
                "target": ["params", "body"]
            },
            {
                "id": "SQLI-005", "name": "SQL Hex/Encoded Payloads",
                "category": "SQL Injection", "severity": 80,
                "patterns": [
                    r"0x[0-9a-fA-F]{4,}", r"CHARs*(s*d+)",
                    r"CONCATs*(", r"CONVERTs*(", r"CASTs*(",
                ],
                "description": "Detects hex-encoded or function-based SQLi payloads",
                "target": ["params", "body", "url"]
            },
            {
                "id": "SQLI-006", "name": "SQL Information Schema Access",
                "category": "SQL Injection", "severity": 85,
                "patterns": [
                    r"(bINFORMATION_SCHEMAb)", r"(bTABLE_NAMEb)",
                    r"(bCOLUMN_NAMEb)", r"(bsys.(tables|columns|objects)b)",
                    r"(bsqlite_masterb)",
                ],
                "description": "Detects information_schema enumeration attempts",
                "target": ["params", "body", "url"]
            },
            
            # XSS
            {
                "id": "XSS-001", "name": "Script Tag Injection",
                "category": "XSS", "severity": 90,
                "patterns": [
                    r"<script[^>]*>.*?</script>", r"<script[^>]*>", r"</script>",
                ],
                "description": "Detects script tag injection attempts",
                "target": ["params", "body", "url", "headers"]
            },
            {
                "id": "XSS-002", "name": "JavaScript Event Handlers",
                "category": "XSS", "severity": 85,
                "patterns": [
                    r"bonw+s*=s*['"][^'"]*['"]", r"bonw+s*=s*`[^`]*`",
                    r"bonw+s*=s*[^s>]+", r"bonerrorb", r"bonloadb",
                    r"bonclickb", r"bonmouseoverb", r"bonfocusb",
                    r"bonchangeb", r"bonsubmitb",
                ],
                "description": "Detects inline JavaScript event handlers",
                "target": ["params", "body", "url"]
            },
            {
                "id": "XSS-003", "name": "JavaScript Protocol and Functions",
                "category": "XSS", "severity": 90,
                "patterns": [
                    r"javascripts*:", r"(balertbs*()", r"(bconfirmbs*()",
                    r"(bpromptbs*()", r"(bdocument.w+b)", r"(bwindow.w+b)",
                    r"(bevalbs*()", r"(bsetTimeoutbs*()", r"(bsetIntervalbs*()",
                ],
                "description": "Detects javascript: protocol and dangerous JS function calls",
                "target": ["params", "body", "url", "headers"]
            },
            {
                "id": "XSS-004", "name": "HTML Tag Injection",
                "category": "XSS", "severity": 75,
                "patterns": [
                    r"<img[^>]*bonw+s*=", r"<img[^>]*bsrcs*=s*['"].*['"]",
                    r"<iframe[^>]*>", r"<embed[^>]*>", r"<object[^>]*>",
                    r"<svg[^>]*bonw+s*=", r"<svg[^>]*>",
                    r"<body[^>]*bonw+s*=", r"<input[^>]*bonw+s*=",
                    r"<a[^>]*bhrefs*=s*['"]javascript:",
                ],
                "description": "Detects dangerous HTML tags commonly used in XSS",
                "target": ["params", "body", "url"]
            },
            
            # LFI/RFI
            {
                "id": "LFI-001", "name": "Directory Traversal",
                "category": "LFI/RFI", "severity": 85,
                "patterns": [
                    r"../", r"..\", r"..%2f", r"..%5c",
                    r"%2e%2e%2f", r"%2e%2e%5c", r"../../", r"..\..\",
                ],
                "description": "Detects directory traversal path sequences",
                "target": ["params", "url"]
            },
            {
                "id": "LFI-002", "name": "Sensitive File Access",
                "category": "LFI/RFI", "severity": 90,
                "patterns": [
                    r"(etc/passwd|etc/shadow|etc/hosts)",
                    r"(boot.ini|win.ini|system.ini)", r"(windows\system32)",
                    r"(Proc/self/environ|proc/self/fd)", r"(.env|.git/config|.](streamdown:incomplete-link)