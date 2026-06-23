#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SentinelShield: Advanced Intrusion Detection & Web Protection System
Python Backend Server - Serves separate HTML template
"""

import os
import re
import json
import time
import hashlib
import datetime
import threading
import http.server
import urllib.parse
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, deque


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
    DASHBOARD_DIR = "dashboard"
    TEMPLATES_DIR = "templates"
    SEVERITY_THRESHOLD_BLOCK = 50
    SEVERITY_THRESHOLD_WARN = 20
    DASHBOARD_REFRESH_SECONDS = 5
    
    @classmethod
    def ensure_dirs(cls):
        for d in [cls.LOG_DIR, cls.DASHBOARD_DIR, cls.TEMPLATES_DIR]:
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
            # ---- SQL Injection ----
            {
                "id": "SQLI-001", "name": "Union-Based SQL Injection",
                "category": "SQL Injection", "severity": 90,
                "patterns": [
                    r"(UNION\s+ALL\s+SELECT)", r"(UNION\s+SELECT)",
                    r"(UNION\s+.*SELECT)",
                ],
                "description": "Detects UNION SELECT SQL injection attempts",
                "target": ["params", "body", "url"]
            },
            {
                "id": "SQLI-002", "name": "Classic SQL Injection",
                "category": "SQL Injection", "severity": 85,
                "patterns": [
                    r"('|\")\s*(OR|AND)\s+['\"]?\s*['\"]?",
                    r"(OR|AND)\s+1\s*=\s*1", r"(OR|AND)\s+1\s*=\s*0",
                    r"(OR|AND)\s+'1'\s*=\s*'1'", r"(OR|AND)\s+\"1\"\s*=\s*\"1\"",
                ],
                "description": "Detects classic OR 1=1 SQL injection",
                "target": ["params", "body", "url"]
            },
            {
                "id": "SQLI-003", "name": "SQL Comment Injection",
                "category": "SQL Injection", "severity": 75,
                "patterns": [r"--\s*$", r"#\s*$", r"/\*.*\*/"],
                "description": "Detects SQL comment injection",
                "target": ["params", "body"]
            },
            {
                "id": "SQLI-004", "name": "SQL Command Execution",
                "category": "SQL Injection", "severity": 95,
                "patterns": [
                    r"(EXEC|EXECUTE)", r"(xp_cmdshell)", r"(INTO\s+OUTFILE)",
                    r"(INTO\s+DUMPFILE)", r"(LOAD_FILE)", r"(WAITFOR\s+DELAY)",
                    r"(SLEEP\s*\(\s*\d+\s*\))", r"(BENCHMARK\s*\()",
                ],
                "description": "Detects SQL command execution and time-based injection",
                "target": ["params", "body"]
            },
            {
                "id": "SQLI-005", "name": "SQL Encoded Payloads",
                "category": "SQL Injection", "severity": 80,
                "patterns": [
                    r"0x[0-9a-fA-F]{4,}", r"CHAR\s*\(\s*\d+",
                    r"CONCAT\s*\(", r"CONVERT\s*\(", r"CAST\s*\(",
                ],
                "description": "Detects hex-encoded SQLi payloads",
                "target": ["params", "body", "url"]
            },
            {
                "id": "SQLI-006", "name": "SQL Schema Access",
                "category": "SQL Injection", "severity": 85,
                "patterns": [
                    r"(INFORMATION_SCHEMA)", r"(TABLE_NAME)", r"(COLUMN_NAME)",
                    r"(sys\.(tables|columns|objects))", r"(sqlite_master)",
                ],
                "description": "Detects information_schema enumeration",
                "target": ["params", "body", "url"]
            },
            
            # ---- XSS ----
            {
                "id": "XSS-001", "name": "Script Tag Injection",
                "category": "XSS", "severity": 90,
                "patterns": [
                    r"<script[^>]*>.*?</script>", r"<script[^>]*>", r"</script>",
                ],
                "description": "Detects script tag injection",
                "target": ["params", "body", "url", "headers"]
            },
            {
                "id": "XSS-002", "name": "JavaScript Event Handlers",
                "category": "XSS", "severity": 85,
                "patterns": [
                    r"\bon\w+\s*=\s*['\"][^'\"]*['\"]", r"\bon\w+\s*=\s*`[^`]*`",
                    r"\bon\w+\s*=\s*[^\s>]+", r"\bonerror\b", r"\bonload\b",
                    r"\bonclick\b", r"\bonmouseover\b", r"\bonfocus\b",
                    r"\bonchange\b", r"\bonsubmit\b",
                ],
                "description": "Detects inline JavaScript event handlers",
                "target": ["params", "body", "url"]
            },
            {
                "id": "XSS-003", "name": "JavaScript Protocol",
                "category": "XSS", "severity": 90,
                "patterns": [
                    r"javascript\s*:", r"(alert\s*\()", r"(confirm\s*\()",
                    r"(prompt\s*\()", r"(document\.\w+)", r"(window\.\w+)",
                    r"(eval\s*\()", r"(setTimeout\s*\()", r"(setInterval\s*\()",
                ],
                "description": "Detects javascript: protocol and dangerous JS calls",
                "target": ["params", "body", "url", "headers"]
            },
            {
                "id": "XSS-004", "name": "HTML Tag Injection",
                "category": "XSS", "severity": 75,
                "patterns": [
                    r"<img[^>]*\bon\w+\s*=", r"<img[^>]*\bsrc\s*=\s*['\"].*['\"]",
                    r"<iframe[^>]*>", r"<embed[^>]*>", r"<object[^>]*>",
                    r"<svg[^>]*\bon\w+\s*=", r"<svg[^>]*>",
                    r"<body[^>]*\bon\w+\s*=", r"<input[^>]*\bon\w+\s*=",
                    r"<a[^>]*\bhref\s*=\s*['\"]javascript:",
                ],
                "description": "Detects dangerous HTML tags for XSS",
                "target": ["params", "body", "url"]
            },
            
            # ---- LFI/RFI ----
            {
                "id": "LFI-001", "name": "Directory Traversal",
                "category": "LFI/RFI", "severity": 85,
                "patterns": [
                    r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c",
                    r"%2e%2e%2f", r"%2e%2e%5c", r"\.\./\.\./", r"\.\.\\\.\.\\",
                ],
                "description": "Detects directory traversal path sequences",
                "target": ["params", "url"]
            },
            {
                "id": "LFI-002", "name": "Sensitive File Access",
                "category": "LFI/RFI", "severity": 90,
                "patterns": [
                    r"(etc/passwd|etc/shadow|etc/hosts)", r"(boot\.ini|win\.ini|system\.ini)",
                    r"(windows\\system32)", r"(Proc/self/environ|proc/self/fd)",
                    r"(\.env|\.git/config|\.svn/entries)", r"(config\.php|db\.php|admin\.php)",
                    r"(php://input|php://filter|php://stdin)", r"(data://|expect://|zip://|compress\.)",
                ],
                "description": "Detects attempts to read sensitive files",
                "target": ["params", "url"]
            },
            {
                "id": "LFI-003", "name": "Remote File Inclusion",
                "category": "LFI/RFI", "severity": 95,
                "patterns": [
                    r"(https?://|ftp://)[^\s\"'>]+\.(php|txt|html?|inc|asp|jsp)",
                ],
                "description": "Detects remote file inclusion attempts",
                "target": ["params", "body", "url"]
            },
            
            # ---- Command Injection ----
            {
                "id": "CMD-001", "name": "System Command Execution",
                "category": "Command Injection", "severity": 95,
                "patterns": [
                    r"[;&|`]\s*(cat|ls|dir|pwd|whoami|id|uname|hostname|ifconfig|ipconfig|netstat|ps|top|kill|rm|mv|cp|chmod|chown|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php|node)",
                    r"\$\(.*\)", r"`.*`", r"\{\$.*\}",
                ],
                "description": "Detects shell command injection",
                "target": ["params", "body", "url", "headers"]
            },
            {
                "id": "CMD-002", "name": "Command Chaining",
                "category": "Command Injection", "severity": 90,
                "patterns": [
                    r"[;&|]{2,}", r"\|\s*$", r";\s*$", r"&\s*$",
                    r"\$\s*\(", r"\)\s*\$",
                ],
                "description": "Detects command chaining operators",
                "target": ["params", "body", "url"]
            },
            {
                "id": "CMD-003", "name": "Reverse Shell Indicators",
                "category": "Command Injection", "severity": 100,
                "patterns": [
                    r"(bash|sh|python|perl|nc|ncat|socat).*[-].*[i]",
                    r"(/dev/tcp/|/dev/udp/)", r"(mknod|mkfifo)",
                    r"(reverse|shell|backconnect)",
                ],
                "description": "Detects reverse shell payload patterns",
                "target": ["params", "body", "url"]
            },
            
            # ---- SSRF ----
            {
                "id": "SSRF-001", "name": "Server-Side Request Forgery",
                "category": "SSRF", "severity": 85,
                "patterns": [
                    r"(https?://)(127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.1[6-9]\..*|172\.2[0-9]\..*|172\.3[0-1]\..*|192\.168\..*|169\.254\..*)",
                    r"(http://\[::1\]|http://0x7f000001|http://0177\.0\.0\.1|http://2130706433)",
                ],
                "description": "Detects SSRF attempts targeting internal resources",
                "target": ["params", "body", "url"]
            },
            
            # ---- User Agent ----
            {
                "id": "UA-001", "name": "Suspicious User-Agent",
                "category": "Reconnaissance", "severity": 40,
                "patterns": [
                    r"(sqlmap|nikto|nmap|dirbuster|gobuster|wfuzz|zap|burp|acunetix|netsparker|appscan)",
                    r"(python-requests|python-urllib|Go-http-client|libwww-perl|curl|wget)",
                    r"(masscan|zmap|hydra|medusa|john|hashcat)",
                ],
                "description": "Detects security scanners via User-Agent",
                "target": ["headers"]
            },
            
            # ---- HTTP Method ----
            {
                "id": "HTTP-001", "name": "Unsafe HTTP Method",
                "category": "HTTP Method Abuse", "severity": 50,
                "patterns": [r"^(PUT|DELETE|TRACE|CONNECT|OPTIONS|PATCH)\s"],
                "description": "Detects unsafe HTTP methods",
                "target": ["method"]
            },
        ]
    
    def _compile_rules(self) -> List[Dict]:
        compiled = []
        for rule in self.rules:
            rule_copy = rule.copy()
            rule_copy["compiled"] = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in rule["patterns"]]
            compiled.append(rule_copy)
        return compiled
    
    def inspect(self, data: str, target: str = "params") -> List[Dict]:
        matches = []
        if not data or not isinstance(data, str):
            return matches
        
        for rule in self.compiled_rules:
            if target not in rule.get("target", ["params"]):
                continue
            
            for pattern in rule["compiled"]:
                match = pattern.search(data)
                if match:
                    matches.append({
                        "id": rule["id"], "name": rule["name"],
                        "category": rule["category"], "severity": rule["severity"],
                        "matched": match.group(0)[:100], "description": rule["description"],
                    })
                    break
        
        return matches


# ============================================================
# RATE LIMITER
# ============================================================

class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60, ban_duration: int = 300):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ban_duration = ban_duration
        self.ip_tracking: Dict[str, deque] = defaultdict(deque)
        self.banned_ips: Dict[str, float] = {}
        self.lock = threading.Lock()
    
    def record_request(self, ip: str) -> Dict:
        now = time.time()
        with self.lock:
            if ip in self.banned_ips:
                if now < self.banned_ips[ip]:
                    return {
                        "status": "blocked", "reason": "IP banned",
                        "remaining_ban": self.banned_ips[ip] - now,
                        "request_count": len(self.ip_tracking[ip]),
                    }
                else:
                    del self.banned_ips[ip]
            
            ip_deque = self.ip_tracking[ip]
            while ip_deque and ip_deque[0] < now - self.window_seconds:
                ip_deque.popleft()
            
            ip_deque.append(now)
            count = len(ip_deque)
            
            if count > self.max_requests:
                self.banned_ips[ip] = now + self.ban_duration
                return {
                    "status": "banned",
                    "reason": f"Rate limit exceeded: {count} requests in {self.window_seconds}s",
                    "request_count": count, "ban_duration": self.ban_duration,
                }
            
            return {"status": "allowed", "request_count": count, "remaining": self.max_requests - count}
    
    def get_traffic_summary(self) -> Dict:
        with self.lock:
            now = time.time()
            active_ips = 0
            total_requests = 0
            top_ips = []
            
            for ip, timestamps in self.ip_tracking.items():
                while timestamps and timestamps[0] < now - self.window_seconds:
                    timestamps.popleft()
                if timestamps:
                    active_ips += 1
                    total_requests += len(timestamps)
                    top_ips.append((ip, len(timestamps)))
            
            top_ips.sort(key=lambda x: x[1], reverse=True)
            
            return {
                "active_ips": active_ips,
                "total_requests_last_window": total_requests,
                "window_seconds": self.window_seconds,
                "max_per_ip": self.max_requests,
                "top_ips": top_ips[:20],
                "banned_ips": list(self.banned_ips.keys()),
                "banned_count": len(self.banned_ips),
            }


# ============================================================
# LOGGER
# ============================================================

class Logger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.text_log = os.path.join(log_dir, "sentinel_shield.log")
        self.json_log = os.path.join(log_dir, "events.json")
        self.access_log = os.path.join(log_dir, "access.log")
        self.events_buffer = []
        self.max_buffer = 1000
        self.lock = threading.Lock()
        
        if not os.path.exists(self.json_log):
            with open(self.json_log, 'w', encoding='utf-8') as f:
                json.dump([], f)
    
    def log_event(self, event: Dict):
        now = datetime.datetime.now()
        event["timestamp"] = now.isoformat()
        event["epoch"] = time.time()
        
        if "id" not in event:
            event["id"] = hashlib.md5(
                f"{event['timestamp']}{event.get('ip','')}{event.get('rule_id','')}".encode()
            ).hexdigest()[:12]
        
        with self.lock:
            # Write to text log
            log_line = (
                f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"IP: {event.get('ip', 'unknown'):<15} "
                f"Status: {event.get('status', 'unknown'):<10} "
                f"Category: {event.get('category', 'unknown'):<20} "
                f"Rule: {event.get('rule_id', 'N/A'):<15} "
                f"Severity: {event.get('severity', 0):<5} "
                f"Method: {event.get('method', 'GET'):<6} "
                f"Path: {event.get('path', '/')}\n"
            )
            with open(self.text_log, 'a', encoding='utf-8') as f:
                f.write(log_line)
            
            # Write to JSON log
            json_events = []
            try:
                with open(self.json_log, 'r', encoding='utf-8') as f:
                    json_events = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                json_events = []
            
            json_events.append(event)
            if len(json_events) > 10000:
                json_events = json_events[-10000:]
            
            with open(self.json_log, 'w', encoding='utf-8') as f:
                json.dump(json_events, f, indent=2)
            
            # Update buffer
            self.events_buffer.append(event)
            if len(self.events_buffer) > self.max_buffer:
                self.events_buffer = self.events_buffer[-self.max_buffer:]
    
    def log_access(self, ip: str, method: str, path: str, status: int,
                   size: int, user_agent: str, duration_ms: float):
        now = datetime.datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')
        log_line = (
            f'{ip} - - [{now}] "{method} {path} HTTP/1.1" {status} {size} '
            f'"-" "{user_agent}" {duration_ms:.2f}ms\n'
        )
        with open(self.access_log, 'a', encoding='utf-8') as f:
            f.write(log_line)
    
    def get_recent_events(self, count: int = 50) -> List[Dict]:
        with self.lock:
            return list(self.events_buffer[-count:])
    
    def get_event_summary(self) -> Dict:
        with self.lock:
            events = self.events_buffer
            summary = {
                "total_events": len(events),
                "by_category": defaultdict(int),
                "by_severity": defaultdict(int),
                "by_ip": defaultdict(int),
                "blocked_count": 0,
                "allowed_count": 0,
                "recent_timeline": [],
            }
            
            for e in events:
                summary["by_category"][e.get("category", "unknown")] += 1
                summary["by_severity"][e.get("severity", 0)] += 1
                summary["by_ip"][e.get("ip", "unknown")] += 1
                if e.get("status") == "blocked":
                    summary["blocked_count"] += 1
                else:
                    summary["allowed_count"] += 1
            
            now = time.time()
            for i in range(10, 0, -1):
                start = now - (i * 60)
                end = now - ((i - 1) * 60)
                count = sum(1 for e in events if start <= e.get("epoch", 0) <= end)
                summary["recent_timeline"].append({"minute": f"{i-1}-{i} min ago", "count": count})
            
            return dict(summary)


# ============================================================
# REQUEST PROCESSOR
# ============================================================

class RequestProcessor:
    def __init__(self, rule_engine: RuleEngine, rate_limiter: RateLimiter, logger: Logger):
        self.rule_engine = rule_engine
        self.rate_limiter = rate_limiter
        self.logger = logger
    
    def process_request(self, ip: str, method: str, path: str, headers: Dict,
                        params: Dict, body: str = "") -> Dict:
        now = time.time()
        result = {
            "ip": ip, "method": method, "path": path,
            "timestamp": datetime.datetime.now().isoformat(), "epoch": now,
            "status": "allowed", "detections": [], "severity_score": 0,
            "rate_limit_info": None, "response_code": 200, "blocked_by": None,
        }
        
        # Step 1: Rate limit check
        if Config.RATE_LIMIT_ENABLED:
            rate_status = self.rate_limiter.record_request(ip)
            result["rate_limit_info"] = rate_status
            
            if rate_status["status"] in ("blocked", "banned"):
                result["status"] = "blocked"
                result["blocked_by"] = "rate_limiter"
                result["response_code"] = 429
                result["rate_limit_info"] = rate_status
                self._log_detection(result, {
                    "rule_id": "RATE-001", "rule_name": "Rate Limit Exceeded",
                    "category": "Rate Limiting", "severity": 60,
                    "matched": f"{rate_status.get('request_count', 0)} requests in window",
                    "description": rate_status.get("reason", "Rate limit triggered"),
                })
                return result
        
        # Step 2: Build request parts
        request_parts = {
            "url": path,
            "params": "&".join(f"{k}={v}" for k, v in params.items()),
            "body": body,
            "headers": " ".join(f"{k}: {v}" for k, v in headers.items()),
            "method": method,
        }
        
        # Step 3: Run rules
        all_detections = []
        max_severity = 0
        
        for target_name, target_data in request_parts.items():
            if not target_data:
                continue
            matches = self.rule_engine.inspect(target_data, target=target_name)
            for match in matches:
                if match not in all_detections:
                    all_detections.append(match)
                    max_severity = max(max_severity, match["severity"])
        
        result["detections"] = all_detections
        result["severity_score"] = max_severity
        
        # Step 4: Decision
        if all_detections:
            worst = max(all_detections, key=lambda x: x["severity"])
            
            if worst["severity"] >= Config.SEVERITY_THRESHOLD_BLOCK:
                result["status"] = "blocked"
                result["blocked_by"] = "rule_engine"
                result["response_code"] = 403
                result["block_reason"] = worst["name"]
                self._log_detection(result, worst)
                
            elif worst["severity"] >= Config.SEVERITY_THRESHOLD_WARN:
                result["status"] = "monitored"
                result["response_code"] = 200
                result["warning"] = worst["name"]
                self._log_detection(result, worst)
            
            for detection in all_detections:
                self._log_detection(result, detection, log_only=True)
        
        return result
    
    def _log_detection(self, result: Dict, detection: Dict, log_only: bool = False):
        log_entry = {
            "ip": result["ip"], "method": result["method"], "path": result["path"],
            "status": "monitored" if log_only else result.get("status", "allowed"),
            "rule_id": detection.get("id", "UNKNOWN"),
            "rule_name": detection.get("name", "Unknown"),
            "category": detection.get("category", "Unknown"),
            "severity": detection.get("severity", 0),
            "matched_content": detection.get("matched", ""),
            "description": detection.get("description", ""),
            "severity_score": result.get("severity_score", 0),
            "response_code": result.get("response_code", 200),
        }
        self.logger.log_event(log_entry)


# ============================================================
# HTTP SERVER
# ============================================================

class SentinelShieldHandler(http.server.BaseHTTPRequestHandler):
    rule_engine = None
    rate_limiter = None
    logger = None
    request_processor = None
    dashboard_html = None
    
    def do_GET(self):
        self._handle_request("GET")
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length > 0 else ""
        self._handle_request("POST", body)
    
    def do_PUT(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='replace') if content_length > 0 else ""
        self._handle_request("PUT", body)
    
    def do_DELETE(self):
        self._handle_request("DELETE")
    
    def do_OPTIONS(self):
        self._handle_request("OPTIONS")
    
    def do_HEAD(self):
        self._handle_request("HEAD")
    
    def _handle_request(self, method: str, body: str = ""):
        start_time = time.time()
        
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        params = dict(urllib.parse.parse_qsl(parsed_path.query))
        headers = dict(self.headers)
        
        ip = self.client_address[0]
        if 'X-Forwarded-For' in headers:
            ip = headers['X-Forwarded-For'].split(',')[0].strip()
        
        # === Route: Dashboard ===
        if path == "/" or path == "/dashboard" or path == "/index.html":
            self._serve_dashboard()
            duration_ms = (time.time() - start_time) * 1000
            self.logger.log_access(ip, method, "/dashboard", 200,
                                 len(self.dashboard_html or ""),
                                 headers.get('User-Agent', '-'), duration_ms)
            return
        
        # === Route: API Events ===
        if path == "/api/events":
            self._serve_json_events()
            return
        
        # === Route: API Summary ===
        if path == "/api/summary":
            self._serve_json_summary()
            return
        
        # === Route: Log Files ===
        if path.startswith("/logs/"):
            self._serve_log_file(path)
            return
        
        # === Process all other requests through WAF ===
        result = self.request_processor.process_request(
            ip=ip, method=method, path=path,
            headers=headers, params=params, body=body,
        )
        
        duration_ms = (time.time() - start_time) * 1000
        
        if result["status"] == "blocked":
            if result.get("blocked_by") == "rate_limiter":
                self._send_response(429, "Rate limit exceeded. Try again later.\n")
            else:
                self._send_blocked_page(result)
        else:
            self._send_response(200, f"Request allowed.\nPath: {path}\nMethod: {method}\n")
        
        self.logger.log_access(ip, method, path, result["response_code"],
                             len(result.get("detections", [])),
                             headers.get('User-Agent', '-'), duration_ms)
    
    def _send_response(self, code: int, message, content_type: str = "text/plain"):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-SentinelShield', 'protected')
        self.end_headers()
        
        if isinstance(message, str):
            self.wfile.write(message.encode('utf-8'))
        else:
            self.wfile.write(message)
    
    def _serve_dashboard(self):
        """Serve the dashboard HTML template"""
        with open(os.path.join(Config.TEMPLATES_DIR, "dashboard.html"), 'r', encoding='utf-8') as f:
            self.dashboard_html = f.read()
        self._send_response(200, self.dashboard_html, content_type="text/html")
    
    def _serve_json_events(self):
        """Serve recent events as JSON"""
        events = self.logger.get_recent_events(100)
        self._send_response(200, json.dumps(events, indent=2), content_type="application/json")
    
    def _serve_json_summary(self):
        """Serve summary as JSON"""
        summary = self.logger.get_event_summary()
        traffic = self.rate_limiter.get_traffic_summary()
        self._send_response(200, json.dumps({"summary": summary, "traffic": traffic}, indent=2),
                          content_type="application/json")
    
    def _serve_log_file(self, path: str):
        """Serve log files"""
        filename = path.replace("/logs/", "")
        log_path = os.path.join(Config.LOG_DIR, filename)
        if os.path.exists(log_path) and os.path.isfile(log_path):
            with open(log_path, 'rb') as f:
                content = f.read()
            self._send_response(200, content, content_type="text/plain")
        else:
            self._send_response(404, "Log file not found.\n")
    
    def _send_blocked_page(self, result: Dict):
        """Send a blocked request response"""
        block_reason = result.get("block_reason", "Malicious request detected")
        details = result.get("detections", [{}])[0] if result.get("detections") else {}
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Request Blocked - SentinelShield</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0;
               display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .container {{ max-width: 600px; padding: 40px; text-align: center; }}
        h1 {{ color: #ff4757; margin-bottom: 16px; }}
        .reason {{ background: #1a2332; border: 1px solid #ff4757; border-radius: 8px;
                   padding: 16px; margin: 20px 0; color: #ffa502; }}
        .detail {{ color: #667788; font-size: 14px; margin-top: 12px; }}
        .ip {{ color: #556677; font-size: 12px; margin-top: 24px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Request Blocked</h1>
        <p>SentinelShield has blocked this request.</p>
        <div class="reason">
            <strong>Reason:</strong> {block_reason}
        </div>
        <div class="detail">
            Severity Score: {result.get('severity_score', 0)} |
            Category: {details.get('category', 'Unknown')}
        </div>
        <div class="ip">IP: {result.get('ip', 'unknown')} |
             Timestamp: {result.get('timestamp', 'N/A')}</div>
    </div>
</body>
</html>"""
        self._send_response(403, html, content_type="text/html")
    
    def log_message(self, format, *args):
        pass  # Suppress default HTTP server logging


# ============================================================
# MAIN APPLICATION
# ============================================================

class SentinelShield:
    def __init__(self):
        Config.ensure_dirs()
        
        # Initialize components
        self.rule_engine = RuleEngine()
        self.rate_limiter = RateLimiter(
            max_requests=Config.MAX_REQUESTS_PER_WINDOW,
            window_seconds=Config.RATE_WINDOW_SECONDS,
            ban_duration=Config.BAN_DURATION_SECONDS,
        )
        self.logger = Logger(Config.LOG_DIR)
        self.request_processor = RequestProcessor(self.rule_engine, self.rate_limiter, self.logger)
        
        # Configure handler
        SentinelShieldHandler.rule_engine = self.rule_engine
        SentinelShieldHandler.rate_limiter = self.rate_limiter
        SentinelShieldHandler.logger = self.logger
        SentinelShieldHandler.request_processor = self.request_processor
        SentinelShieldHandler.dashboard_html = None
    
    def start(self):
        server = http.server.HTTPServer((Config.HOST, Config.PORT), SentinelShieldHandler)
        
        print(f"""
=============================================================================
|            SentinelShield is ACTIVE                                        |
|  Advanced Intrusion Detection & Web Protection System                      |
=============================================================================
|  Dashboard:    http://localhost:{Config.PORT}/                               |
|  API Events:   http://localhost:{Config.PORT}/api/events                    |
|  API Summary:  http://localhost:{Config.PORT}/api/summary                   |
|  Logs:         http://localhost:{Config.PORT}/logs/                         |
=============================================================================
|  Rules Loaded: {len(self.rule_engine.rules):<42}|
|  Rate Limit:   {Config.MAX_REQUESTS_PER_WINDOW} req/{Config.RATE_WINDOW_SECONDS}s window{' ':<18}|
|  Ban Duration: {Config.BAN_DURATION_SECONDS}s{' ':<49}|
|  Block Threshold: Severity >= {Config.SEVERITY_THRESHOLD_BLOCK}{' ':<31}|
=============================================================================
|  Press Ctrl+C to stop                                                      |
=============================================================================
""")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[SentinelShield] Shutting down...")
            server.shutdown()


if __name__ == "__main__":
    shield = SentinelShield()
    shield.start()  