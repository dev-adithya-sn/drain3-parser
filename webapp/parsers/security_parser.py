"""
Security log field extractor — universal, directional, structured.

Extracts a comprehensive security event record from ANY log format:

    WHO:    source_user, target_user, user_role, user_agent
    WHAT:   action, event_type, status, severity, error_code, message
    WHERE:  source_ip, dest_ip, source_port, dest_port,
            source_host, dest_host, source_mac, dest_mac
    WHEN:   timestamp
    HOW:    protocol, http_method, http_status, http_path
    TARGET: resource, file_path, url, service, process, pid,
            database, registry_key
    CONTEXT: bytes_in, bytes_out, duration, session_id, request_id,
             trace_id, region
    THREAT: threat indicators (auth_failure, brute_force, etc.)
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Iterable

from .base import LogParser, ParseResult, ParsedRecord, ClusterInfo

# ── Structured extraction schema ─────────────────────────────────────────────

@dataclass
class SecurityEvent:
    """Comprehensive security event — every field a SOC analyst needs."""
    # WHEN
    timestamp:     str = ""
    # WHO
    source_user:   str = ""
    target_user:   str = ""
    user_role:     str = ""
    user_agent:    str = ""
    # WHAT
    action:        str = ""    # login, deny, block, create, delete, execute, etc.
    event_type:    str = ""    # authentication, network, file, process, system, etc.
    status:        str = ""    # success, failure
    severity:      str = ""    # emergency, alert, critical, error, warning, info, debug
    error_code:    str = ""
    message:       str = ""
    # WHERE — source
    source_ip:     str = ""
    source_port:   str = ""
    source_host:   str = ""
    source_mac:    str = ""
    # WHERE — destination
    dest_ip:       str = ""
    dest_port:     str = ""
    dest_host:     str = ""
    dest_mac:      str = ""
    # extra IPs/hosts found without clear direction
    other_ips:     list[str] = field(default_factory=list)
    other_hosts:   list[str] = field(default_factory=list)
    # HOW
    protocol:      str = ""
    http_method:   str = ""
    http_status:   str = ""
    http_path:     str = ""
    # TARGET (what was accessed/affected)
    resource:      str = ""
    file_path:     str = ""
    url:           str = ""
    service:       str = ""
    process:       str = ""
    pid:           str = ""
    database:      str = ""
    registry_key:  str = ""
    # CONTEXT
    bytes_in:      str = ""
    bytes_out:     str = ""
    duration:      str = ""
    session_id:    str = ""
    request_id:    str = ""
    trace_id:      str = ""
    region:        str = ""
    # THREAT
    threats:       list[str] = field(default_factory=list)

    def to_summary(self) -> list[str]:
        """Flat labeled list matching the universal security schema."""
        out = []
        # maps SecurityEvent attr → universal_schema.yml field name
        LABELS = {
            "timestamp":    "timestamp",
            "severity":     "log_level",
            "event_type":   "event_type",
            "action":       "action",
            "source_user":  "who_user",
            "process":      "who_process",
            "pid":          "who_userid",
            "source_host":  "src_machine",
            "dest_host":    "dst_machine",
            "status":       "status",
            "source_mac":   "src_mac",
            "dest_mac":     "dst_mac",
            "source_ip":    "src_ip",
            "dest_ip":      "dst_ip",
            "source_port":  "src_port",
            "dest_port":    "dst_port",
            "protocol":     "protocol",
            "target_user":  "to_user",
            "resource":     "resource",
            "file_path":    "resource",
            "url":          "resource",
            "service":      "resource",
            "user_agent":   "who_user_agent",
            "http_method":  "action",
            "http_status":  "status",
            "http_path":    "resource",
            "region":       "region",
            "session_id":   "session_id",
            "request_id":   "request_id",
            "trace_id":     "trace_id",
            "bytes_in":     "bytes_in",
            "bytes_out":    "bytes_out",
            "duration":     "duration",
        }
        seen = set()
        for attr, label in LABELS.items():
            val = getattr(self, attr)
            if val:
                key = f"{label}={val}"
                if key not in seen:
                    out.append(key)
                    seen.add(key)
        for ip in self.other_ips:
            out.append(f"ip={ip}")
        for h in self.other_hosts:
            out.append(f"host={h}")
        for t in self.threats:
            out.append(f"⚠{t}")
        return out


# ── Pattern-based extractors ──────────────────────────────────────────────────
# Run in order: specific → general. Each match is replaced with a mask
# before the next pattern runs, preventing double-extraction.

_PIPELINE: list[tuple[re.Pattern, str, str]] = []

def _p(pattern: str, field_name: str, mask: str, flags=0):
    _PIPELINE.append((re.compile(pattern, flags), field_name, mask))

# --- Timestamps (most specific first) ---
_p(r"\b\d{4}-\d{2}-\d{2}[T_ ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", "timestamp", "<TIMESTAMP>")
_p(r"\b\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+\b", "timestamp", "<TIMESTAMP>")
_p(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d+)?", "timestamp", "<TIMESTAMP>")
_p(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?", "timestamp", "<TIMESTAMP>")
_p(r"\b\d{2}/\d{2}/\d{2,4} \d{2}:\d{2}:\d{2}\b", "timestamp", "<TIMESTAMP>")
_p(r"\b\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\b", "timestamp", "<TIMESTAMP>")
_p(r"\b\d{6} \d{6}\b", "timestamp", "<TIMESTAMP>")

# --- URLs (before IPs, so http://1.2.3.4/path is one URL not an IP + path) ---
_p(r"\bhttps?://\S+", "url", "<URL>")
_p(r"\bftp://\S+", "url", "<URL>")

# --- Network: IPs with directional context ---
_p(r"(?i)\b(?:src|source|from|client)[-_ ]?(?:ip|addr(?:ess)?)?[= :]+(\d{1,3}(?:\.\d{1,3}){3})", "source_ip", "<SRC_IP>")
_p(r"(?i)\b(?:dst|dest|destination|to|server|target)[-_ ]?(?:ip|addr(?:ess)?)?[= :]+(\d{1,3}(?:\.\d{1,3}){3})", "dest_ip", "<DST_IP>")
_p(r"(?i)\bfrom (?:host )?(\d{1,3}(?:\.\d{1,3}){3})", "source_ip", "<SRC_IP>")
_p(r"(?i)\bto (\d{1,3}(?:\.\d{1,3}){3})", "dest_ip", "<DST_IP>")
# generic IPs (no clear direction)
_p(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?\b", "other_ip", "<IP>")

# --- MACs with direction ---
_p(r"(?i)\b(?:src|source)[-_ ]?mac[= :]+([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", "source_mac", "<SRC_MAC>")
_p(r"(?i)\b(?:dst|dest)[-_ ]?mac[= :]+([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", "dest_mac", "<DST_MAC>")
_p(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b", "other_mac", "<MAC>")

# --- Ports with direction ---
_p(r"(?i)\b(?:src|source)[-_ ]?port[= :]+(\d{1,5})\b", "source_port", "<SRC_PORT>")
_p(r"(?i)\b(?:dst|dest|destination|dpt)[= :]+(\d{1,5})\b", "dest_port", "<DST_PORT>")
_p(r"(?i)\bport[= :]+(\d{1,5})\b", "other_port", "<PORT>")

# --- Users with direction ---
_p(r"(?i)\bfor (?:(?:invalid )?user )?([a-zA-Z0-9._@-]+)\s+from\b", "target_user", "<TGT_USER>")
_p(r"(?i)\b(?:src[-_ ]?user|actor|principal|caller|authenticated as)[= :]+['\"]?([a-zA-Z0-9._@-]+)['\"]?", "source_user", "<SRC_USER>")
_p(r"(?i)\b(?:dst[-_ ]?user|target[-_ ]?user|runas|switch(?:ed)? to)[= :]+['\"]?([a-zA-Z0-9._@-]+)['\"]?", "target_user", "<TGT_USER>")
_p(r"(?i)\b(?:user|username|usr|login|account)[= :]+['\"]?([a-zA-Z0-9._@-]+)['\"]?", "source_user", "<USER>")
_p(r"(?i)\buser '([^']+)'", "source_user", "<USER>")
_p(r'(?i)\buser "([^"]+)"', "source_user", "<USER>")

# --- Emails ---
_p(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "email", "<EMAIL>")

# --- Identifiers ---
_p(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "uuid", "<UUID>")
_p(r"\b0[xX][0-9a-fA-F]+\b", "hex", "<HEX>")

# --- Process / PID ---
_p(r"(?i)\b(?:pid|process_id|processid)[= :]+(\d+)\b", "pid", "<PID>")
_p(r"(?i)\b(?:process|proc|program)[= :]+([a-zA-Z0-9._-]+)", "process", "<PROCESS>")

# --- HTTP ---
_p(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b", "http_method", "<METHOD>")
_p(r'(?:GET|POST|PUT|DELETE|PATCH|HEAD) (/\S+)', "http_path", "<HTTP_PATH>")
_p(r'HTTP/[12]\.[01]"\s+(\d{3})', "http_status", "<HTTP_STATUS>")
_p(r"(?i)\b(?:status[-_ ]?code|response[-_ ]?code|http[-_ ]?status)[= :]+(\d{3})\b", "http_status", "<HTTP_STATUS>")
_p(r"\bHTTP/[12]\.[01]\b", "http_version", "<HTTP_VER>")

# --- Protocol ---
_p(r"(?i)\b(TCP|UDP|ICMP|SSH|HTTPS|HTTP|FTP|SMTP|DNS|SNMP|TLS|SSL|RDP|SMB|LDAP|NTP|DHCP|ARP|IMAP|POP3)\b", "protocol", "<PROTO>")

# --- Severity ---
_p(r"\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE|FATAL|SEVERE)\b", "severity", "<LEVEL>", re.I)

# --- Action keywords ---
_p(r"(?i)\b((?:log(?:ged)?[ -]?(?:in|out|on|off))|(?:sign(?:ed)?[ -]?(?:in|out))|login|logout|logon|logoff)\b", "action", "<ACTION>")
_p(r"(?i)\b(accepted|rejected|denied|refused|blocked|dropped|allowed|permitted|granted|failed|succeeded|created|deleted|modified|updated|started|stopped|installed|removed|executed|terminated|suspended|resumed|opened|closed|connected|disconnected)\b", "action", "<ACTION>")

# --- Event type inference ---
_p(r"(?i)\b(authenticat\w+|authoriz\w+|password|credential|token|cert(?:ificate)?|key(?:store)?)\b", "event_type_hint", "<EVT>")
_p(r"(?i)\b(firewall|iptables|netfilter|pf|nftables|acl)\b", "event_type_hint", "<EVT>")

# --- Resources ---
_p(r"(?i)\b(?:file|path)[= :]+['\"]?(/[a-zA-Z0-9._/-]+)['\"]?", "file_path", "<FILE>")
_p(r"(?i)\b(?:table|database|db|schema)[= :]+['\"]?([a-zA-Z0-9._-]+)['\"]?", "database", "<DB>")
_p(r"(?i)\b(?:service|daemon|app(?:lication)?)[= :]+['\"]?([a-zA-Z0-9._-]+)['\"]?", "service", "<SERVICE>")
_p(r"(?i)\b(?:registry|regkey|hklm|hkcu)[= :]*([a-zA-Z0-9\\_/-]+)", "registry_key", "<REGKEY>")

# --- Context ---
_p(r"(?i)\b(?:bytes[-_ ]?(?:in|recv|received|rx))[= :]+(\d+)\b", "bytes_in", "<BYTES_IN>")
_p(r"(?i)\b(?:bytes[-_ ]?(?:out|sent|tx))[= :]+(\d+)\b", "bytes_out", "<BYTES_OUT>")
_p(r"(?i)\b(?:bytes|size|length)[= :]+(\d+)\b", "bytes_out", "<BYTES>")
_p(r"(?i)\b(?:duration|elapsed|took|latency|time)[= :]+(\d+(?:\.\d+)?)\s*(?:ms|s|sec|seconds|milliseconds)?\b", "duration", "<DURATION>")
_p(r"(?i)\b(?:session[-_ ]?id|sid)[= :]+['\"]?([a-zA-Z0-9._-]+)['\"]?", "session_id", "<SESSION>")
_p(r"(?i)\b(?:request[-_ ]?id|req[-_ ]?id|x-request-id)[= :]+['\"]?([a-zA-Z0-9._-]+)['\"]?", "request_id", "<REQ_ID>")
_p(r"(?i)\b(?:trace[-_ ]?id)[= :]+['\"]?([a-zA-Z0-9._-]+)['\"]?", "trace_id", "<TRACE>")
_p(r"(?i)\b(?:region|az|zone|datacenter|dc)[= :]+['\"]?([a-zA-Z0-9._-]+)['\"]?", "region", "<REGION>")
_p(r"(?i)\b(?:user[-_ ]?agent)[= :]+['\"]?(.+?)['\"]?\s*$", "user_agent", "<UA>")

# --- Hostnames (after other extractions to avoid false positives) ---
_p(r"(?i)\b(?:src[-_ ]?host|source[-_ ]?host|client[-_ ]?host)[= :]+([a-zA-Z0-9._-]+)", "source_host", "<SRC_HOST>")
_p(r"(?i)\b(?:dst[-_ ]?host|dest[-_ ]?host|server[-_ ]?host|target[-_ ]?host)[= :]+([a-zA-Z0-9._-]+)", "dest_host", "<DST_HOST>")
_p(r"(?i)\b(?:host(?:name)?|node|machine|server|computer)[= :]+['\"]?([a-zA-Z][a-zA-Z0-9._-]{2,})['\"]?", "other_host", "<HOST>")

# --- File paths (standalone, after all key=value extractions) ---
_p(r"(?:/[a-zA-Z0-9._-]+){2,}", "file_path", "<PATH>")
_p(r"[A-Z]:\\(?:[a-zA-Z0-9._-]+\\){1,}[a-zA-Z0-9._-]*", "file_path", "<WIN_PATH>")

# --- Time (bare HH:MM:SS, after timestamps have been masked) ---
_p(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b", "_time", "<TIME>")

# --- Generic numbers (always last) ---
_p(r"(?<![A-Za-z_./-])\d{2,}(?![A-Za-z_./-])", "_number", "<NUM>")


# ── Threat heuristics ─────────────────────────────────────────────────────────

_THREATS = [
    (re.compile(r"(?i)\bfailed (?:password|login|auth)"), "auth_failure"),
    (re.compile(r"(?i)\binvalid user\b"), "invalid_user"),
    (re.compile(r"(?i)\b(?:access )?denied\b"), "access_denied"),
    (re.compile(r"(?i)\b(?:brute.?force|too many|repeated|multiple failed)"), "brute_force"),
    (re.compile(r"(?i)\b(?:root|admin|administrator|system)\b"), "privileged_account"),
    (re.compile(r"(?i)\b(?:drop(?:ped)?|reject(?:ed)?|block(?:ed)?|firewall)"), "firewall_action"),
    (re.compile(r"(?i)\b(?:overflow|injection|xss|csrf|traversal|sqlmap|rfi|lfi)"), "attack_signature"),
    (re.compile(r"(?i)\b(?:malware|trojan|virus|ransomware|exploit|backdoor|rootkit|c2|c&c)"), "malware_indicator"),
    (re.compile(r"(?i)\b(?:privilege|sudo|su |escalat|setuid|chmod)"), "privilege_event"),
    (re.compile(r"(?i)\b(?:scan|nmap|probe|sweep|recon|enumerat)"), "recon_indicator"),
    (re.compile(r"(?i)\b(?:exfiltrat|upload|transfer|leak|tunnel|covert)"), "data_exfil"),
    (re.compile(r"(?i)\b(?:timeout|unreachable|refused|reset|connection.?lost)"), "connection_issue"),
    (re.compile(r"(?i)\b(?:401|403|forbidden|unauthorized)\b"), "access_control"),
    (re.compile(r"(?i)\b(?:500|502|503|504|internal.?server.?error)"), "server_error"),
    (re.compile(r"(?i)\b(?:encrypt|decrypt|certificate|ssl|tls|handshake)"), "crypto_event"),
    (re.compile(r"(?i)\b(?:lateral|pivot|pass.the.hash|pass.the.ticket|mimikatz|kerberoast)"), "lateral_movement"),
    (re.compile(r"(?i)\b(?:cron|scheduled|at |task.?schedul)"), "scheduled_task"),
    (re.compile(r"(?i)\b(?:dns|resolve|nslookup|dig |nxdomain)"), "dns_event"),
]


# ── Core extraction ───────────────────────────────────────────────────────────

# Map from _PIPELINE field_name → SecurityEvent attribute + mode
# mode: "first" = keep first value only, "append" = add to a list
_FIELD_MAP = {
    "timestamp":      ("timestamp", "first"),
    "source_ip":      ("source_ip", "first"),
    "dest_ip":        ("dest_ip", "first"),
    "other_ip":       ("other_ips", "append"),
    "source_port":    ("source_port", "first"),
    "dest_port":      ("dest_port", "first"),
    "other_port":     (None, "port_infer"),   # special: infer direction
    "source_mac":     ("source_mac", "first"),
    "dest_mac":       ("dest_mac", "first"),
    "other_mac":      (None, "mac_infer"),
    "source_host":    ("source_host", "first"),
    "dest_host":      ("dest_host", "first"),
    "other_host":     ("other_hosts", "append"),
    "source_user":    ("source_user", "first"),
    "target_user":    ("target_user", "first"),
    "url":            ("url", "first"),
    "email":          (None, "skip"),
    "uuid":           ("request_id", "first"),
    "hex":            (None, "skip"),
    "pid":            ("pid", "first"),
    "process":        ("process", "first"),
    "http_method":    ("http_method", "first"),
    "http_path":      ("http_path", "first"),
    "http_status":    ("http_status", "first"),
    "http_version":   (None, "skip"),
    "protocol":       ("protocol", "first"),
    "severity":       ("severity", "first"),
    "action":         ("action", "first"),
    "event_type_hint":("event_type", "first"),
    "file_path":      ("file_path", "first"),
    "database":       ("database", "first"),
    "service":        ("service", "first"),
    "registry_key":   ("registry_key", "first"),
    "bytes_in":       ("bytes_in", "first"),
    "bytes_out":      ("bytes_out", "first"),
    "duration":       ("duration", "first"),
    "session_id":     ("session_id", "first"),
    "request_id":     ("request_id", "first"),
    "trace_id":       ("trace_id", "first"),
    "region":         ("region", "first"),
    "user_agent":     ("user_agent", "first"),
    "_time":          (None, "skip"),
    "_number":        (None, "skip"),
}


def extract(log: str) -> tuple[SecurityEvent, str]:
    """
    Extract all security fields from a raw log line.
    Returns (SecurityEvent, template_string).
    """
    event = SecurityEvent()
    working = log

    for regex, field_name, mask in _PIPELINE:
        for match in regex.finditer(working):
            value = match.group(1) if match.lastindex else match.group(0)
            mapping = _FIELD_MAP.get(field_name)
            if not mapping:
                continue

            attr, mode = mapping
            if mode == "first" and attr:
                if not getattr(event, attr):
                    setattr(event, attr, value)
            elif mode == "append" and attr:
                lst = getattr(event, attr)
                if value not in lst:
                    lst.append(value)
            elif mode == "port_infer":
                if not event.source_port:
                    event.source_port = value
                elif not event.dest_port:
                    event.dest_port = value
            elif mode == "mac_infer":
                if not event.source_mac:
                    event.source_mac = value
                elif not event.dest_mac:
                    event.dest_mac = value

        working = regex.sub(mask, working)

    # promote first other_ip to source/dest if those are empty
    if event.other_ips:
        if not event.source_ip:
            event.source_ip = event.other_ips.pop(0)
        if event.other_ips and not event.dest_ip:
            event.dest_ip = event.other_ips.pop(0)

    # infer status from action keywords
    if not event.status:
        low = log.lower()
        if any(w in low for w in ("failed", "failure", "denied", "rejected", "error", "invalid")):
            event.status = "failure"
        elif any(w in low for w in ("accepted", "succeeded", "success", "granted", "allowed", "permitted")):
            event.status = "success"

    # infer event_type from context
    if not event.event_type:
        low = log.lower()
        if any(w in low for w in ("auth", "login", "logon", "password", "credential", "sshd", "pam")):
            event.event_type = "authentication"
        elif any(w in low for w in ("firewall", "iptables", "drop", "block", "acl", "netfilter")):
            event.event_type = "firewall"
        elif any(w in low for w in ("get ", "post ", "put ", "http", "request", "response", "nginx", "apache")):
            event.event_type = "web"
        elif any(w in low for w in ("file", "read", "write", "open", "close", "chmod", "chown")):
            event.event_type = "file"
        elif any(w in low for w in ("process", "exec", "fork", "kill", "pid", "spawn")):
            event.event_type = "process"
        elif any(w in low for w in ("dns", "resolve", "lookup", "nxdomain")):
            event.event_type = "dns"
        elif any(w in low for w in ("connect", "disconnect", "tcp", "udp", "socket", "port")):
            event.event_type = "network"

    # threat indicators
    for regex, tag in _THREATS:
        if regex.search(log):
            event.threats.append(tag)

    return event, working


# ── JSON-aware field mapping ──────────────────────────────────────────────────

_JSON_KEY_MAP = {
    "timestamp": "timestamp", "time": "timestamp", "datetime": "timestamp",
    "@timestamp": "timestamp", "eventtime": "timestamp", "ts": "timestamp",
    "created_at": "timestamp", "logged_at": "timestamp", "date": "timestamp",

    "level": "severity", "severity": "severity", "loglevel": "severity",
    "priority": "severity",

    "message": "message", "msg": "message", "log": "message",
    "description": "message", "detail": "message",

    "source": "service", "service": "service", "app": "service",
    "application": "service", "logger": "service", "eventsource": "service",

    "host": "source_host", "hostname": "source_host", "server": "dest_host",
    "node": "source_host", "computer_name": "source_host",

    "ip": "source_ip", "src_ip": "source_ip", "source_ip": "source_ip",
    "sourceipaddress": "source_ip", "client_ip": "source_ip", "remote_addr": "source_ip",
    "dst_ip": "dest_ip", "dest_ip": "dest_ip", "destination_ip": "dest_ip",

    "port": "dest_port", "src_port": "source_port", "dst_port": "dest_port",
    "sourceport": "source_port", "destinationport": "dest_port",

    "user": "source_user", "username": "source_user", "userid": "source_user",
    "actor": "source_user", "principal": "source_user",
    "target_user": "target_user", "runas_user": "target_user",

    "method": "http_method", "request_method": "http_method",
    "status": "http_status", "status_code": "http_status", "response_code": "http_status",
    "path": "http_path", "url": "url", "uri": "url", "request_uri": "url",

    "pid": "pid", "process_id": "pid", "process": "process",
    "action": "action", "eventname": "action", "operation": "action",
    "errorcode": "error_code", "error": "error_code",
    "awsregion": "region", "region": "region",
    "useragent": "user_agent", "user_agent": "user_agent",
    "traceid": "trace_id", "trace_id": "trace_id", "spanid": "trace_id",
    "requestid": "request_id", "request_id": "request_id", "eventid": "request_id",
    "sessionid": "session_id", "session_id": "session_id",
    "protocol": "protocol", "proto": "protocol",
    "bytes": "bytes_out", "bytes_sent": "bytes_out", "bytes_received": "bytes_in",
    "duration": "duration", "elapsed": "duration", "latency": "duration",
}


def _enrich_from_json(event: SecurityEvent, log: str) -> None:
    """If the log is JSON, extract fields from known keys."""
    log = log.strip()
    if not (log.startswith("{") and log.endswith("}")):
        return
    try:
        obj = json.loads(log)
    except (json.JSONDecodeError, ValueError):
        return

    def walk(d):
        if isinstance(d, dict):
            for k, v in d.items():
                key_lower = k.lower().replace("-", "_")
                if key_lower in _JSON_KEY_MAP and isinstance(v, (str, int, float, bool)):
                    attr = _JSON_KEY_MAP[key_lower]
                    if hasattr(event, attr) and not getattr(event, attr):
                        setattr(event, attr, str(v))
                elif isinstance(v, dict):
                    walk(v)

    walk(obj)


# ── LogParser implementation ──────────────────────────────────────────────────

SAMPLE_RECORDS = 500


# ── Multi-line log joiner ─────────────────────────────────────────────────────

_ENTRY_START = re.compile(
    r"^(?:"
    r"\d{4}-\d{2}-\d{2}[T ]"           # ISO timestamp
    r"|[A-Z][a-z]{2} \d{1,2} \d{2}:"   # syslog (Jan 15 10:)
    r"|\d{2}-\d{2} \d{2}:\d{2}:"       # Android (03-17 16:13:)
    r"|\d{6} \d{6}"                     # HDFS (081109 203615)
    r"|<\d+>"                           # syslog priority (<134>)
    r"|\{\"timestamp"                   # JSON logs
    r'|\{"@timestamp'
    r'|\{"time"'
    r"|CEF:"                            # CEF format
    r"|\d+\.\d+\.\d+\.\d+ - "          # access logs (IP - user)
    r"|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+"  # firewall (src dst)
    r")"
)


def join_multiline(lines: Iterable[str]) -> Iterable[str]:
    """
    Join multi-line log entries into single lines.

    A new entry starts when a line matches a known log-start pattern
    (timestamp, JSON, CEF, IP prefix, etc.). Everything else is a
    continuation of the previous entry, joined with " | ".

    This handles:
    - Java/Python stack traces
    - Multi-line error messages
    - Wrapped syslog entries
    - Any log where continuation lines lack a timestamp
    """
    buffer = ""
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if _ENTRY_START.match(line):
            if buffer:
                yield buffer
            buffer = line
        else:
            buffer += " | " + line.strip()
    if buffer:
        yield buffer


class SecurityParser(LogParser):
    """
    Universal security log field extractor.
    
    Field extraction: regex pipeline (WHO/WHAT/WHERE/WHEN/HOW).
    Clustering: drain3 under the hood (similarity-based, not exact-match).
    Multi-line: continuation lines joined before parsing.
    """
    name = "security"

    def parse(self, lines: Iterable[str],
              sample_limit: int = SAMPLE_RECORDS) -> ParseResult:

        # join multi-line entries (stack traces, wrapped messages)
        lines = join_multiline(lines)

        # use drain3 for clustering — it handles similarity-based merging
        import os
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig

        cfg = TemplateMinerConfig()
        config_file = os.environ.get("DRAIN3_CONFIG", "drain3.ini")
        if os.path.exists(config_file):
            cfg.load(config_file)
        miner = TemplateMiner(config=cfg)

        records:       list[ParsedRecord] = []
        total_lines    = 0
        total_params   = 0
        new_clusters   = 0

        for raw in lines:
            log = raw.rstrip("\n")
            if not log.strip():
                continue

            # 1. security field extraction (labeled WHO/WHAT/WHERE)
            event, masked_template = extract(log)
            _enrich_from_json(event, log)

            # 2. drain3 clustering on the masked template (similarity-based)
            result = miner.add_log_message(masked_template)
            cluster_id = result["cluster_id"]
            drain_template = result["template_mined"]
            change = result["change_type"]

            summary = event.to_summary()
            total_lines  += 1
            total_params += len(summary)
            if change == "new":
                new_clusters += 1

            if len(records) < sample_limit:
                records.append(ParsedRecord(
                    original_log = log,
                    cluster_id   = cluster_id,
                    template     = drain_template,
                    parameters   = summary,
                    change_type  = change,
                ))

        # build cluster list from drain3's tree
        clusters = []
        for c in miner.drain.id_to_cluster.values():
            clusters.append(ClusterInfo(c.cluster_id, c.size, c.get_template()))
        clusters.sort(key=lambda c: c.size, reverse=True)

        result = ParseResult(self.name, records, clusters)
        result._total_lines  = total_lines
        result._total_params = total_params
        result._new_clusters = new_clusters
        return result
