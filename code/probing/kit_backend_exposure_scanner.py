#!/usr/bin/env python3

import argparse
import csv
import json
import os
import re
import urllib.request
import urllib.error
from urllib.parse import quote
from typing import Dict, List, Tuple


TEXT_EXTS = {
    ".php", ".html", ".htm", ".js", ".css", ".txt", ".log", ".json",
    ".env", ".ini", ".conf", ".yaml", ".yml", ".md", ".xml", ".sh",
}

DOCKER_FILES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".dockerignore",
}

ADMIN_PATH_HINTS = (
    "admin", "cpanel", "panel", "dashboard", "manage", "backend",
)

PHP_FILE_UPLOAD_PATTERNS = [
    r"move_uploaded_file\s*\(",
    r"\$_FILES\s*\[",
]

PHP_LFI_PATTERNS = [
    r"(include|require|include_once|require_once)\s*\(\s*\$_(GET|REQUEST|POST)\s*\[",
    r"readfile\s*\(\s*\$_(GET|REQUEST|POST)\s*\[",
]

PHP_RCE_PATTERNS = [
    r"(eval|assert|system|shell_exec|passthru|exec|popen|proc_open)\s*\(",
]

PHP_SQLI_PATTERNS = [
    r"(mysql_query|mysqli_query|pg_query|PDO::query)\s*\(",
    r"SELECT\s+.+\.\s*\$_(GET|POST|REQUEST)",
    r"INSERT\s+.+\.\s*\$_(GET|POST|REQUEST)",
]

ATTACKER_LOGIC_PATTERNS = {
    # NOTE: these indicate phishing functionality, not server exposure vulnerability.
    "credential_collection": [
        r"\$_POST\s*\[\s*['\"](password|pass|pwd|user|username|email|login)['\"]\s*\]",
    ],
    "exfil_mail": [
        r"@?mail\s*\(",
    ],
    "local_dump_write": [
        r"fopen\s*\(",
        r"fwrite\s*\(",
    ],
}

SECRET_PATTERNS = {
    "telegram_bot_token": r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b",
    "db_password_literal": r"(?i)\b(db_pass|db_password)\b\s*[:=]\s*['\"][^'\"]+['\"]",
    "api_key_like": r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"][^'\"]+['\"]",
}

CREDENTIAL_DUMP_PATTERNS = [
    r"(?i)\b(email|username|user|login)\b.{0,20}\b(password|pass|pwd)\b",
    r"(?i)\bcard(number)?\b",
    r"(?i)\bcvv\b",
]

EXTERNAL_INPUT_MARKERS = [
    r"\$_GET\s*\[",
    r"\$_POST\s*\[",
    r"\$_REQUEST\s*\[",
    r"\$_COOKIE\s*\[",
    r"\$_FILES\s*\[",
    r"php://input",
]

SQLI_PREPARED_HINTS = [
    r"->\s*prepare\s*\(",
    r"\bprepare\s*\(",
    r"bind_param\s*\(",
    r"bindValue\s*\(",
    r"bindParam\s*\(",
]

OPSEC_LOG_NAME_HINTS = (
    "error_log", "debug.log", "php_error.log", "php-error.log", "trace.log",
    "stacktrace", "exception.log", "runtime.log",
)

OPSEC_LOG_CONTENT_PATTERNS = [
    r"(?i)\bphp (warning|notice|fatal error|parse error)\b",
    r"(?i)\bstack trace\b",
    r"(?i)\buncaught exception\b",
    r"(?i)\bcall to undefined function\b",
]

DIR_LISTING_ENABLE_PATTERNS = [
    # Apache: "Options +Indexes" or "Options Indexes" in .htaccess/httpd.conf
    r"(?i)\boptions\b[^\n\r]{0,60}\+?indexes\b",
    # nginx: autoindex on;
    r"(?i)\bautoindex\s+on\s*;",
    # NOTE: DirectoryIndex is intentionally excluded -- it sets the default
    # index filename and does NOT enable directory listing. Including it
    # was a source of false positives.
]

WORDPRESS_PATH_HINTS = (
    "wp-admin/",
    "wp-includes/",
    "wp-content/plugins/",
    "wp-content/themes/",
    "wp-config.php",
    "wp-login.php",
    "xmlrpc.php",
)

WORDPRESS_CORE_PATH_PREFIXES = (
    "wp-admin/",
    "wp-includes/",
)

WORDPRESS_INJECTION_PATTERNS = [
    r"(?i)eval\s*\(\s*base64_decode\s*\(",
    r"(?i)gzinflate\s*\(\s*base64_decode\s*\(",
    r"(?i)preg_replace\s*\(.*/e",
    r"(?i)assert\s*\(\s*\$_(POST|GET|REQUEST)",
    r"(?i)(system|exec|shell_exec|passthru)\s*\(\s*\$_(POST|GET|REQUEST)",
]

PLACEHOLDER_SECRET_HINTS = [
    "example.com", "your_token_here", "your_api_key", "changeme", "placeholder",
    "test@example.com", "@wordpress.org", "your-bot-token", "insert_token",
    # NOTE: "noreply@" removed -- attackers legitimately use noreply@ addresses;
    # filtering on this prefix would silently drop real attacker emails.
]

WRITE_TARGET_PATTERNS = [
    r"fopen\s*\(\s*['\"]([^'\"]+\.(?:txt|log|csv|dat))['\"]",
    r"file_put_contents\s*\(\s*['\"]([^'\"]+\.(?:txt|log|csv|dat))['\"]",
]

# ---------------------------------------------------------------------------
# Backend misconfiguration (PHP / deployment) -- goal: exploitable misconfigs
# ---------------------------------------------------------------------------
PHP_VERBOSE_ERROR_PATTERNS = [
    r"(?i)\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?1['\"]?\s*\)",
    r"(?i)\bdisplay_errors\s*=\s*1\b",
    r"(?i)\berror_reporting\s*\(\s*(E_ALL|E_STRICT|32767)\s*\)",
    r"(?i)\bphp_flag\s+display_errors\s+on\b",
]

CORS_LOOSE_PATTERNS = [
    r"(?i)Access-Control-Allow-Origin\s*['\"]\s*\*\s*['\"]",
    r"(?i)header\s*\(\s*['\"]Access-Control-Allow-Origin:\s*\*",
    r"(?i)['\"]Access-Control-Allow-Origin:\s*\*['\"]",
]

CHMOD_WORLD_WRITABLE_PATTERNS = [
    r"(?i)chmod\s*\(\s*[^,]+,\s*0777\s*\)",
    r"(?i)chmod\s*\(\s*[^,]+,\s*0o777\s*\)",
    r"(?i)\bchmod\s+['\"]?777['\"]?\b",
]

WEAK_DEFAULT_CREDENTIAL_PATTERNS = [
    r"(?i)password\s*[:=]\s*['\"]?(admin|password|12345|123456|qwerty|test)['\"]?\b",
    r"(?i)\b(mysql|db)_password\s*[:=]\s*['\"]?[^'\"]{0,12}['\"]?",
]

PHP_ALLOW_URL_INCLUDE_PATTERNS = [
    r"(?i)\ballow_url_include\s*=\s*On\b",
    r"(?i)\bini_set\s*\(\s*['\"]allow_url_include['\"]\s*,\s*['\"]1['\"]\s*\)",
]


def read_text_file(path: str, max_bytes: int = 1024 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def safe_text(s: str) -> str:
    """Remove invalid surrogate characters that break UTF-8 output."""
    if not isinstance(s, str):
        return s
    # drop lone surrogate code points (U+D800..U+DFFF)
    return re.sub(r"[\ud800-\udfff]", "", s)


def sanitize_obj(obj):
    """Recursively sanitize strings for JSON/CSV serialization."""
    if isinstance(obj, str):
        return safe_text(obj)
    if isinstance(obj, list):
        return [sanitize_obj(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(sanitize_obj(x) for x in obj)
    if isinstance(obj, dict):
        return {sanitize_obj(k): sanitize_obj(v) for k, v in obj.items()}
    return obj


def all_files(root: str) -> List[str]:
    paths = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            paths.append(os.path.join(dp, fn))
    return paths


def has_text_ext(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in TEXT_EXTS or os.path.basename(path).lower() in DOCKER_FILES


def find_pattern_hits(content: str, patterns: List[str]) -> List[str]:
    hits = []
    for pat in patterns:
        if re.search(pat, content, re.IGNORECASE):
            hits.append(pat)
    return hits


def collect_regex_evidence(content: str, patterns: List[str], max_hits: int = 5) -> List[str]:
    """Compact evidence strings: line=<n> pattern=<regex> code=<snippet>."""
    evidences = []
    seen = set()
    for pat in patterns:
        try:
            for m in re.finditer(pat, content, re.IGNORECASE):
                line_no = content.count("\n", 0, m.start()) + 1
                start = content.rfind("\n", 0, m.start()) + 1
                end = content.find("\n", m.start())
                if end == -1:
                    end = len(content)
                snippet = content[start:end].strip()
                snippet = re.sub(r"\s+", " ", snippet)[:120]
                ev = f"line={line_no} pattern={pat} code={snippet}"
                if ev not in seen:
                    evidences.append(ev)
                    seen.add(ev)
                if len(evidences) >= max_hits:
                    return evidences
        except re.error:
            continue
    return evidences


def _line_context(lines: List[str], idx: int, before: int = 2, after: int = 2) -> str:
    s = max(0, idx - before)
    e = min(len(lines), idx + after + 1)
    merged = " | ".join(lines[s:e]).strip()
    return re.sub(r"\s+", " ", merged)[:240]


def _has_external_input(text: str) -> bool:
    for pat in EXTERNAL_INPUT_MARKERS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def collect_sink_evidence_with_taint(
    content: str,
    sink_patterns: List[str],
    max_hits: int = 5,
    lookback_lines: int = 6,
) -> Tuple[List[str], List[str]]:
    """Return (tainted_hits, potential_hits) with context snippets.

    Tainted means external HTTP input appears in sink line or nearby dataflow.
    Potential means sink exists but taint source was not observed in local context.
    """
    lines = content.splitlines()
    tainted = []
    potential = []

    for i, line in enumerate(lines):
        matched = None
        for pat in sink_patterns:
            try:
                if re.search(pat, line, re.IGNORECASE):
                    matched = pat
                    break
            except re.error:
                continue
        if not matched:
            continue

        ctx_start = max(0, i - lookback_lines)
        local_block = "\n".join(lines[ctx_start:i + 1])
        is_tainted = _has_external_input(local_block)

        ev = (
            f"line={i+1} tainted={is_tainted} pattern={matched} "
            f"context={_line_context(lines, i)}"
        )
        if is_tainted:
            tainted.append(ev)
        else:
            potential.append(ev)

        if len(tainted) >= max_hits and len(potential) >= max_hits:
            break

    return tainted[:max_hits], potential[:max_hits]


def collect_sqli_evidence(content: str, max_hits: int = 5) -> Tuple[List[str], List[str]]:
    """Return (confirmed_tainted, potential) SQLi evidences.

    confirmed_tainted: query execution + external input observed nearby + no prepared/binding hints nearby.
    potential: query sink exists but taint/prepared certainty is low.
    """
    lines = content.splitlines()
    confirmed = []
    potential = []

    sink_pats = [r"(mysql_query|mysqli_query|pg_query|PDO::query)\s*\("]
    for i, line in enumerate(lines):
        if not any(re.search(p, line, re.IGNORECASE) for p in sink_pats):
            continue

        s = max(0, i - 6)
        e = min(len(lines), i + 4)
        block = "\n".join(lines[s:e])
        has_taint = _has_external_input(block)
        has_prepared_hint = any(re.search(p, block, re.IGNORECASE) for p in SQLI_PREPARED_HINTS)
        ev = (
            f"line={i+1} tainted={has_taint} prepared_hint={has_prepared_hint} "
            f"context={_line_context(lines, i, before=3, after=2)}"
        )

        if has_taint and not has_prepared_hint:
            confirmed.append(ev)
        else:
            potential.append(ev)

        if len(confirmed) >= max_hits and len(potential) >= max_hits:
            break

    return confirmed[:max_hits], potential[:max_hits]


MISCONFIG_PATTERN_GROUPS = [
    ("verbose_error_disclosure", PHP_VERBOSE_ERROR_PATTERNS),
    ("cors_allow_all", CORS_LOOSE_PATTERNS),
    ("world_writable_chmod", CHMOD_WORLD_WRITABLE_PATTERNS),
    ("weak_default_credential_hints", WEAK_DEFAULT_CREDENTIAL_PATTERNS),
    ("allow_url_include_on", PHP_ALLOW_URL_INCLUDE_PATTERNS),
]


def collect_misconfiguration_hits(content: str, rel_path: str, max_per_cat: int = 3) -> Dict[str, List[str]]:
    """Map misconfiguration category -> evidence strings (for backend exploitability goal)."""
    out: Dict[str, List[str]] = {name: [] for name, _ in MISCONFIG_PATTERN_GROUPS}
    for cat, pats in MISCONFIG_PATTERN_GROUPS:
        evi = collect_regex_evidence(content, pats, max_hits=max_per_cat)
        for e in evi:
            out[cat].append(f"{rel_path}::{e}")
    return out


def merge_misconfig_hits(dst: Dict[str, List[str]], src: Dict[str, List[str]]) -> None:
    for k, v in src.items():
        dst.setdefault(k, [])
        for item in v:
            if item not in dst[k]:
                dst[k].append(item)


def compute_misconfig_score(misconfig_hits: Dict[str, List[str]]) -> int:
    """Weighted score for misconfiguration surface (0~+)."""
    w = {
        "verbose_error_disclosure": 3,
        "cors_allow_all": 2,
        "world_writable_chmod": 2,
        "weak_default_credential_hints": 2,
        "allow_url_include_on": 3,
    }
    s = 0
    for k, pts in w.items():
        if misconfig_hits.get(k):
            s += pts
    return s


def build_backend_risk_assessment(
    exposure_hits: Dict,
    misconfig_hits: Dict[str, List[str]],
    misconfig_score: int,
    site_profile: Dict,
) -> Dict:
    """Structured view for methodology: deployment exposure, OPSEC, PHP misconfig, injection."""
    tainted_injection = bool(
        exposure_hits.get("lfi_risk")
        or exposure_hits.get("rce_risk")
        or exposure_hits.get("sqli_risk")
    )
    potential_injection = bool(
        exposure_hits.get("lfi_potential")
        or exposure_hits.get("rce_potential")
        or exposure_hits.get("sqli_potential")
    )
    return {
        "research_goal": "exploitable_misconfigurations_and_architectural_flaws",
        "misconfig_score": misconfig_score,
        "misconfig_categories": {k: len(v) for k, v in misconfig_hits.items()},
        "dimensions": {
            "deployment_exposure": {
                "directory_listing_observed": bool(exposure_hits.get("directory_listing_suspected")),
                "directory_listing_kit_config_evidence": bool(
                    exposure_hits.get("directory_listing_kit_controlled")
                ),
                "sensitive_filename_in_tree": bool(exposure_hits.get("sensitive_file_exposure")),
                "credential_dump_file_in_tree": bool(exposure_hits.get("public_credential_dumps")),
            },
            "operational_opsec": {
                "debug_log_in_tree": bool(exposure_hits.get("opsec_debug_log_exposure")),
                "secret_material_in_tree": bool(exposure_hits.get("secret_leakage")),
            },
            "php_misconfiguration": {
                "verbose_errors": bool(misconfig_hits.get("verbose_error_disclosure")),
                "cors_allow_all": bool(misconfig_hits.get("cors_allow_all")),
                "world_writable_chmod_hint": bool(misconfig_hits.get("world_writable_chmod")),
                "weak_default_credential_literal": bool(
                    misconfig_hits.get("weak_default_credential_hints")
                ),
                "allow_url_include": bool(misconfig_hits.get("allow_url_include_on")),
            },
            "injection_exploitability": {
                "tainted_sink_present": tainted_injection,
                "potential_sink_only": potential_injection and not tainted_injection,
            },
            "compromised_cms_snapshot": {
                "wordpress_structure": bool(site_profile.get("wordpress_structural_hits")),
                "injection_evidence_in_wp": bool(site_profile.get("wordpress_injection_evidence")),
            },
        },
    }


def content_has_attacker_info(content: str) -> bool:
    if not content:
        return False
    # High-confidence secret patterns (token/api/db password)
    for _, sp in SECRET_PATTERNS.items():
        try:
            m = re.search(sp, content)
            if m:
                raw = (m.group(0) or "")[:200]
                if not secret_match_is_placeholder(raw):
                    return True
        except re.error:
            continue
    # Generic email -- only flag if it doesn't look like a plugin/framework default.
    # We require the domain to NOT be a known safe/public domain.
    _SAFE_EMAIL_DOMAINS = {
        "wordpress.org", "example.com", "w3.org", "jquery.com",
        "github.com", "npmjs.com", "getcomposer.org",
    }
    for m in re.finditer(r"(?i)\b([A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,}))\b", content):
        domain = m.group(2).lower()
        if domain not in _SAFE_EMAIL_DOMAINS:
            email = m.group(1).lower()
            if not any(hint in email for hint in PLACEHOLDER_SECRET_HINTS):
                return True
    return False


def detect_wordpress_profile(file_paths: List[str], kit_root: str) -> Dict:
    rels = [rel(p, kit_root).lower() for p in file_paths]
    structural_hits = []
    for rp in rels:
        for h in WORDPRESS_PATH_HINTS:
            if h in rp:
                structural_hits.append(rp)
                break
    structural_hits = sorted(set(structural_hits))

    # conservative: require at least 2 independent WP structures
    is_wp_snapshot = len(structural_hits) >= 2
    return {
        "cms": "wordpress" if is_wp_snapshot else "",
        "wordpress_structural_hits": structural_hits[:40],
        "is_compromised_legit_snapshot": is_wp_snapshot,
        "wordpress_operational_log_hits": [],
        "wordpress_injection_evidence": [],
    }


def is_wordpress_core_path(rp: str) -> bool:
    rpl = (rp or "").lower()
    return any(rpl.startswith(pref) for pref in WORDPRESS_CORE_PATH_PREFIXES)


def secret_match_is_placeholder(raw_match: str) -> bool:
    blob = (raw_match or "").lower()
    return any(k in blob for k in PLACEHOLDER_SECRET_HINTS)


def rel(path: str, root: str) -> str:
    return safe_text(os.path.relpath(path, root).replace("\\", "/"))


def probe_directory_listing(base_url: str, web_root: str, dir_path: str) -> Tuple[bool, str]:
    rel_dir = os.path.relpath(dir_path, web_root).replace("\\", "/")
    if rel_dir == ".":
        url = base_url.rstrip("/") + "/"
    else:
        url = base_url.rstrip("/") + "/" + rel_dir.strip("/") + "/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(200000).decode("utf-8", errors="ignore")
            if "Index of /" in body or "<title>Index of" in body:
                return True, url
    except Exception:
        pass
    return False, url


def file_to_url(file_path: str, web_root: str, base_url: str) -> str:
    try:
        rel_file = os.path.relpath(file_path, web_root).replace("\\", "/")
    except Exception:
        return ""
    if rel_file.startswith(".."):
        return ""
    encoded = "/".join(quote(seg, safe="") for seg in rel_file.split("/"))
    return base_url.rstrip("/") + "/" + encoded


def probe_file_access(url: str) -> Dict:
    result = {
        "url": url,
        "status": None,
        "content_type": "",
        "body_len": 0,
        "credential_like": False,
        "attacker_info_like": False,
        "marker_found": False,
        "error": "",
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body_raw = resp.read(200000)
            body = body_raw.decode("utf-8", errors="ignore")
            result["status"] = getattr(resp, "status", None) or resp.getcode()
            result["content_type"] = resp.headers.get("Content-Type", "")
            result["body_len"] = len(body)
            result["credential_like"] = bool(find_pattern_hits(body, CREDENTIAL_DUMP_PATTERNS))
            result["attacker_info_like"] = content_has_attacker_info(body)
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            body = e.read(50000).decode("utf-8", errors="ignore")
            result["body_len"] = len(body)
            result["credential_like"] = bool(find_pattern_hits(body, CREDENTIAL_DUMP_PATTERNS))
            result["attacker_info_like"] = content_has_attacker_info(body)
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def probe_file_access_with_marker(url: str, marker: str) -> Dict:
    result = probe_file_access(url)
    # Re-fetch a small body for marker check only when needed.
    if not marker:
        return result
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(120000).decode("utf-8", errors="ignore")
            result["marker_found"] = marker in body
            result["status"] = getattr(resp, "status", None) or resp.getcode()
            result["body_len"] = len(body)
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            body = e.read(30000).decode("utf-8", errors="ignore")
            result["marker_found"] = marker in body
            result["body_len"] = len(body)
        except Exception:
            pass
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def create_temp_probe_file(path: str, marker: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("BLACKWIDOW_TEMP_PROBE\n")
            f.write(marker + "\n")
        return True
    except Exception:
        return False


def remove_file_silent(path: str) -> None:
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        pass


def analyze_kit(
    kit_path: str,
    web_root: str = "",
    base_url: str = "",
    live_file_check: bool = False,
    max_file_probes: int = 40,
    temp_probe_create: bool = False,
    max_temp_probes: int = 12,
) -> Dict:
    files = all_files(kit_path)
    site_profile = detect_wordpress_profile(files, kit_path)
    is_wp_snapshot = bool(site_profile.get("is_compromised_legit_snapshot"))
    text_files = [p for p in files if has_text_ext(p)]
    html_files = [p for p in files if os.path.splitext(p)[1].lower() in (".html", ".htm")]
    css_files = [p for p in files if os.path.splitext(p)[1].lower() == ".css"]
    php_files = [p for p in files if os.path.splitext(p)[1].lower() == ".php"]

    exposure_hits = {
        "public_credential_dumps": [],
        "public_credential_dumps_confirmed": [],
        "directory_listing_suspected": [],
        "directory_listing_kit_controlled": [],
        "directory_listing_server_wide_hint": [],
        "file_upload_risk": [],
        "lfi_risk": [],
        "lfi_potential": [],
        "rce_risk": [],
        "rce_potential": [],
        "admin_panel_candidates": [],
        "sqli_risk": [],
        "sqli_potential": [],
        "sensitive_file_exposure": [],
        "sensitive_file_exposure_confirmed": [],
        "opsec_debug_log_exposure": [],
        "opsec_debug_log_exposure_confirmed": [],
        "secret_leakage": [],
        "secret_leakage_confirmed": [],
        "attacker_info_public_exposure_confirmed": [],
        "live_probe_results": [],
        "temp_probe_results": [],
        "policy_exposure_temp_probe_confirmed": [],
    }
    attacker_logic_hits = {
        "credential_collection": [],
        "exfil_mail": [],
        "local_dump_write": [],
    }
    misconfig_hits: Dict[str, List[str]] = {name: [] for name, _ in MISCONFIG_PATTERN_GROUPS}
    dump_candidate_files = set()
    sensitive_candidate_files = set()
    secret_candidate_files = set()
    opsec_log_candidate_files = set()
    write_target_candidate_files = set()

    # File/path based checks
    for p in files:
        rp = rel(p, kit_path)
        rpl = rp.lower()
        bn = os.path.basename(rpl)

        if any(seg in rpl for seg in ADMIN_PATH_HINTS):
            exposure_hits["admin_panel_candidates"].append(rp)

        # Sensitive exposure files
        if bn in {".env", ".git", ".git/config", ".svn", "config.php", "backup.zip", "backup.tar", "db.sql"}:
            exposure_hits["sensitive_file_exposure"].append(rp)
            sensitive_candidate_files.add(p)
        if bn.endswith((".bak", ".old", ".backup", ".swp")):
            exposure_hits["sensitive_file_exposure"].append(rp)
            sensitive_candidate_files.add(p)

        # Potential public credential dump files (name+content heuristic)
        if bn.endswith((".txt", ".log", ".csv")) and any(k in bn for k in ("result", "log", "dump", "credential", "creds", "pass", "data", "lead", "victim", "output")):
            content = read_text_file(p, max_bytes=200000)
            if find_pattern_hits(content, CREDENTIAL_DUMP_PATTERNS):
                exposure_hits["public_credential_dumps"].append(rp)
                dump_candidate_files.add(p)

        # OPSEC debug/error logs can leak attacker infrastructure details.
        # For WP snapshots, logs inside wp-content/wp-admin/wp-includes are
        # the legitimate site's operational logs, not attacker-side leakage --
        # track them separately and do NOT add to exposure_hits.
        if bn in OPSEC_LOG_NAME_HINTS or bn.endswith((".log", ".err")):
            content_log = read_text_file(p, max_bytes=150000)
            if content_log and find_pattern_hits(content_log, OPSEC_LOG_CONTENT_PATTERNS):
                is_wp_operational = is_wp_snapshot and any(
                    seg in rpl for seg in ("wp-content/", "wp-admin/", "wp-includes/")
                )
                if is_wp_operational:
                    site_profile["wordpress_operational_log_hits"].append(rp)
                    # Do NOT add to opsec_debug_log_exposure -- this is the
                    # legitimate site's own log, not an attacker OPSEC failure.
                else:
                    exposure_hits["opsec_debug_log_exposure"].append(rp)
                    opsec_log_candidate_files.add(p)

    # Content checks
    for p in text_files:
        rp = rel(p, kit_path)
        content = read_text_file(p)
        if not content:
            continue

        # Content-first dump detection for .txt/.log/.csv (filename-independent)
        ext = os.path.splitext(p)[1].lower()
        if ext in (".txt", ".log", ".csv"):
            if find_pattern_hits(content, CREDENTIAL_DUMP_PATTERNS):
                exposure_hits["public_credential_dumps"].append(rp)
                dump_candidate_files.add(p)

        if os.path.splitext(p)[1].lower() == ".php":
            merge_misconfig_hits(misconfig_hits, collect_misconfiguration_hits(content, rp))

            up_evi = collect_regex_evidence(content, PHP_FILE_UPLOAD_PATTERNS)
            if up_evi:
                exposure_hits["file_upload_risk"].append(f"{rp}::{up_evi[0]}")

            lfi_tainted, lfi_potential = collect_sink_evidence_with_taint(content, PHP_LFI_PATTERNS)
            if lfi_tainted:
                exposure_hits["lfi_risk"].append(f"{rp}::{lfi_tainted[0]}")
            if lfi_potential:
                exposure_hits["lfi_potential"].append(f"{rp}::{lfi_potential[0]}")

            rce_tainted, rce_potential = collect_sink_evidence_with_taint(content, PHP_RCE_PATTERNS)
            if rce_tainted:
                # WP core files often contain dangerous primitives in benign framework logic.
                if is_wp_snapshot and is_wordpress_core_path(rp):
                    exposure_hits["rce_potential"].append(
                        f"{rp}::{rce_tainted[0]}::wp_core_downgraded=true"
                    )
                else:
                    exposure_hits["rce_risk"].append(f"{rp}::{rce_tainted[0]}")
            if rce_potential:
                exposure_hits["rce_potential"].append(f"{rp}::{rce_potential[0]}")

            sqli_tainted, sqli_potential = collect_sqli_evidence(content)
            if sqli_tainted:
                exposure_hits["sqli_risk"].append(f"{rp}::{sqli_tainted[0]}")
            if sqli_potential:
                exposure_hits["sqli_potential"].append(f"{rp}::{sqli_potential[0]}")

            # Track phishing logic separately (informational only).
            for logic_name, pats in ATTACKER_LOGIC_PATTERNS.items():
                evi = collect_regex_evidence(content, pats)
                if evi:
                    attacker_logic_hits[logic_name].append(f"{rp}::{evi[0]}")

            # Candidate dump targets extracted from write APIs.
            for pat in WRITE_TARGET_PATTERNS:
                try:
                    for m in re.finditer(pat, content, re.IGNORECASE):
                        target = (m.group(1) or "").strip()
                        if not target:
                            continue
                        # Normalize relative to current PHP file directory.
                        if target.startswith("/"):
                            abs_target = os.path.normpath(os.path.join(web_root, target.lstrip("/")))
                        else:
                            abs_target = os.path.normpath(os.path.join(os.path.dirname(p), target))
                        if abs_target.startswith(os.path.normpath(kit_path)):
                            write_target_candidate_files.add(abs_target)
                except re.error:
                    continue

        # Evidence that directory listing may be intentionally enabled in kit config.
        if os.path.basename(p).lower() == ".htaccess" or os.path.splitext(p)[1].lower() in (".conf", ".ini", ".txt"):
            dir_evi = collect_regex_evidence(content, DIR_LISTING_ENABLE_PATTERNS, max_hits=1)
            if dir_evi:
                exposure_hits["directory_listing_kit_controlled"].append(f"{rp}::{dir_evi[0]}")

        for secret_name, sp in SECRET_PATTERNS.items():
            try:
                m = re.search(sp, content)
            except re.error:
                m = None
            if m:
                raw_match = (m.group(0) or "")[:200]
                if secret_match_is_placeholder(raw_match):
                    continue
                # For WP snapshots: skip secrets found inside WP core, vendor
                # subdirectories, and documentation files -- these are from
                # legitimate plugin/theme code, not attacker-added credentials.
                # We intentionally DO NOT skip all of wp-content/plugins/ because
                # attackers may inject their tokens directly into plugin PHP files.
                if is_wp_snapshot:
                    rp_l = rp.lower()
                    if (rp_l.startswith("wp-includes/")
                            or rp_l.startswith("wp-admin/")
                            or "/vendor/" in rp_l
                            or rp_l.endswith(".md")
                            or "/readme" in rp_l):
                        continue
                line_no = content.count("\n", 0, m.start()) + 1
                exposure_hits["secret_leakage"].append(f"{rp}::line={line_no}::{secret_name}")
                secret_candidate_files.add(p)

        # Post-compromise code injection signals in WP snapshots
        if is_wp_snapshot and os.path.splitext(p)[1].lower() in (".php", ".js"):
            inj_evi = collect_regex_evidence(content, WORDPRESS_INJECTION_PATTERNS, max_hits=1)
            if inj_evi:
                site_profile["wordpress_injection_evidence"].append(f"{rp}::{inj_evi[0]}")

    # Optional live check for directory listing
    if base_url and web_root:
        # Baseline probe: if web root itself is listable, listing may be server-wide policy
        # rather than a kit-specific misconfiguration.
        root_listing, root_url = probe_directory_listing(base_url, web_root, web_root)
        if root_listing:
            exposure_hits["directory_listing_server_wide_hint"].append(root_url)

        # Check only a small bounded set to keep runtime practical.
        checked = 0
        for dp, _, _ in os.walk(kit_path):
            if checked >= 50:
                break
            has_listing, url = probe_directory_listing(base_url, web_root, dp)
            checked += 1
            if has_listing:
                exposure_hits["directory_listing_suspected"].append(url)

    # Optional live file-open check: confirm static candidates are actually reachable.
    if live_file_check and base_url and web_root:
        probe_targets = []
        for fp in sorted(dump_candidate_files):
            probe_targets.append((fp, "dump"))
        for fp in sorted(sensitive_candidate_files):
            probe_targets.append((fp, "sensitive"))
        for fp in sorted(opsec_log_candidate_files):
            probe_targets.append((fp, "opsec_log"))
        for fp in sorted(secret_candidate_files):
            probe_targets.append((fp, "secret"))
        for fp in sorted(write_target_candidate_files):
            probe_targets.append((fp, "write_target"))

        seen = set()
        bounded_targets = []
        for fp, typ in probe_targets:
            key = (os.path.normpath(fp), typ)
            if key in seen:
                continue
            seen.add(key)
            bounded_targets.append((fp, typ))
            if len(bounded_targets) >= max_file_probes:
                break

        for fp, typ in bounded_targets:
            if not os.path.isfile(fp):
                continue
            url = file_to_url(fp, web_root, base_url)
            if not url:
                continue
            probe = probe_file_access(url)
            rp = rel(fp, kit_path)
            exposure_hits["live_probe_results"].append(
                f"{rp}::{typ}::status={probe['status']}::cred={probe['credential_like']}::attacker_info={probe['attacker_info_like']}::{probe['url']}"
            )
            if probe["status"] == 200:
                if typ in ("dump", "write_target") and probe["credential_like"]:
                    exposure_hits["public_credential_dumps_confirmed"].append(
                        f"{rp}::status=200::{probe['url']}"
                    )
                if typ == "sensitive":
                    exposure_hits["sensitive_file_exposure_confirmed"].append(
                        f"{rp}::status=200::{probe['url']}"
                    )
                if typ == "opsec_log":
                    exposure_hits["opsec_debug_log_exposure_confirmed"].append(
                        f"{rp}::status=200::{probe['url']}"
                    )
                if typ == "secret" and probe["attacker_info_like"]:
                    exposure_hits["secret_leakage_confirmed"].append(
                        f"{rp}::status=200::{probe['url']}"
                    )
                if probe["attacker_info_like"]:
                    exposure_hits["attacker_info_public_exposure_confirmed"].append(
                        f"{rp}::status=200::{probe['url']}"
                    )

    # Optional temp-file policy probe:
    # create temporary .txt/.log/.csv files and test whether they are
    # externally readable over HTTP (then clean up immediately).
    if temp_probe_create and base_url and web_root:
        candidate_dirs = [kit_path]
        for fp in sorted(write_target_candidate_files):
            d = os.path.dirname(fp)
            if d.startswith(os.path.normpath(kit_path)):
                candidate_dirs.append(d)
        # Keep order deterministic, unique, bounded
        uniq_dirs = []
        seen_dirs = set()
        for d in candidate_dirs:
            nd = os.path.normpath(d)
            if nd in seen_dirs:
                continue
            if not os.path.isdir(nd):
                continue
            seen_dirs.add(nd)
            uniq_dirs.append(nd)

        created = []
        ext_order = [".txt", ".log", ".csv"]
        try:
            idx = 0
            for d in uniq_dirs:
                for ext in ext_order:
                    if len(created) >= max_temp_probes:
                        break
                    marker = f"FA_TEMP_PROBE::{os.path.basename(kit_path)}::{os.getpid()}::{idx}"
                    fname = f"__fa_probe_{os.getpid()}_{idx}{ext}"
                    fpath = os.path.join(d, fname)
                    if create_temp_probe_file(fpath, marker):
                        created.append((fpath, marker))
                        idx += 1
                if len(created) >= max_temp_probes:
                    break

            for fpath, marker in created:
                url = file_to_url(fpath, web_root, base_url)
                if not url:
                    continue
                probe = probe_file_access_with_marker(url, marker)
                rp = rel(fpath, kit_path)
                exposure_hits["temp_probe_results"].append(
                    f"{rp}::status={probe['status']}::marker={probe['marker_found']}::{url}"
                )
                if probe["status"] == 200 and probe["marker_found"]:
                    exposure_hits["policy_exposure_temp_probe_confirmed"].append(
                        f"{rp}::status=200::{url}"
                    )
        finally:
            for fpath, _ in created:
                remove_file_silent(fpath)

    # Deduplicate
    for d in (exposure_hits, attacker_logic_hits):
        for k, v in d.items():
            if isinstance(v, list):
                d[k] = sorted(set(v))
    for k, v in list(misconfig_hits.items()):
        misconfig_hits[k] = sorted(set(v))
    for k, v in list(site_profile.items()):
        if isinstance(v, list):
            site_profile[k] = sorted(set(v))

    exposure_score = 0
    exposure_score += 3 if exposure_hits["public_credential_dumps"] else 0
    exposure_score += 2 if exposure_hits["directory_listing_suspected"] else 0
    exposure_score += 2 if exposure_hits["file_upload_risk"] else 0
    exposure_score += 2 if exposure_hits["lfi_risk"] else 0
    exposure_score += 3 if exposure_hits["rce_risk"] else 0
    exposure_score += 2 if exposure_hits["sqli_risk"] else 0
    exposure_score += 2 if exposure_hits["sensitive_file_exposure"] else 0
    exposure_score += 3 if exposure_hits["secret_leakage"] else 0
    exposure_score += 2 if exposure_hits["opsec_debug_log_exposure"] else 0

    exposure_real_confirmed = bool(
        exposure_hits["public_credential_dumps_confirmed"]
        or exposure_hits["sensitive_file_exposure_confirmed"]
        or exposure_hits["opsec_debug_log_exposure_confirmed"]
        or exposure_hits["secret_leakage_confirmed"]
        or exposure_hits["attacker_info_public_exposure_confirmed"]
    )
    exposure_policy_confirmed = bool(
        exposure_hits["directory_listing_suspected"]
        or exposure_hits["policy_exposure_temp_probe_confirmed"]
    )
    exposure_confirmed = exposure_real_confirmed or exposure_policy_confirmed

    # "Kit-only" policy confirmation: stronger signal for attacker-side OPSEC mistake.
    # - temp probe confirms policy weakness in kit path
    # - directory listing is observed and kit includes listing-enable config evidence
    exposure_policy_confirmed_kit_only = bool(
        exposure_hits["policy_exposure_temp_probe_confirmed"]
        or (
            exposure_hits["directory_listing_suspected"]
            and exposure_hits["directory_listing_kit_controlled"]
        )
    )
    exposure_policy_environmental_only = bool(
        exposure_hits["directory_listing_suspected"]
        and exposure_hits["directory_listing_server_wide_hint"]
        and not exposure_hits["directory_listing_kit_controlled"]
        and not exposure_hits["policy_exposure_temp_probe_confirmed"]
    )
    exposure_confirmed_kit_only = exposure_real_confirmed or exposure_policy_confirmed_kit_only

    misconfig_score = compute_misconfig_score(misconfig_hits)
    # Threshold: any two light misconfigs (2+2) or one heavy (3+) -- tune for paper.
    misconfig_suspected = misconfig_score >= 4
    combined_backend_risk_score = min(
        exposure_score + misconfig_score,
        60,
    )
    backend_risk_assessment = build_backend_risk_assessment(
        exposure_hits,
        misconfig_hits,
        misconfig_score,
        site_profile,
    )

    result = {
        "kit_name": os.path.basename(kit_path.rstrip("/\\")),
        "kit_path": kit_path,
        "file_count": len(files),
        "html_count": len(html_files),
        "css_count": len(css_files),
        "php_count": len(php_files),
        "exposure_score": exposure_score,
        "exposure_suspected": exposure_score >= 5,
        "exposure_real_confirmed": exposure_real_confirmed,
        "exposure_policy_confirmed": exposure_policy_confirmed,
        "exposure_policy_confirmed_kit_only": exposure_policy_confirmed_kit_only,
        "exposure_policy_environmental_only": exposure_policy_environmental_only,
        "exposure_confirmed": exposure_confirmed,
        "exposure_confirmed_kit_only": exposure_confirmed_kit_only,
        "misconfig_score": misconfig_score,
        "misconfig_suspected": misconfig_suspected,
        "combined_backend_risk_score": combined_backend_risk_score,
        "misconfig_hits": misconfig_hits,
        "backend_risk_assessment": backend_risk_assessment,
        "site_profile": site_profile,
        "is_compromised_legit_snapshot": bool(
            site_profile.get("is_compromised_legit_snapshot")
            and (site_profile.get("wordpress_operational_log_hits") or site_profile.get("wordpress_injection_evidence"))
        ),
        "post_compromise_injection_evidence": bool(site_profile.get("wordpress_injection_evidence")),
        "exposure_hits": exposure_hits,
        "attacker_logic_hits": attacker_logic_hits,
    }
    return result


def discover_kits(dataset_root: str) -> List[str]:
    kits = []
    for entry in sorted(os.listdir(dataset_root)):
        p = os.path.join(dataset_root, entry)
        if os.path.isdir(p):
            kits.append(p)
    return kits


def save_csv(results: List[Dict], out_csv: str) -> None:
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "kit_name", "file_count", "html_count", "css_count", "php_count",
            "exposure_score", "misconfig_score", "combined_backend_risk_score",
            "exposure_suspected",
            "exposure_real_confirmed", "exposure_policy_confirmed", "exposure_confirmed",
            "exposure_policy_confirmed_kit_only", "exposure_policy_environmental_only", "exposure_confirmed_kit_only",
            "is_compromised_legit_snapshot", "post_compromise_injection_evidence", "site_profile_cms",
            "wp_structural_hits", "wp_operational_log_hits", "wp_injection_hits",
            "score_flag_exposure_public_credential_dumps",
            "score_flag_exposure_directory_listing",
            "score_flag_exposure_file_upload_risk",
            "score_flag_exposure_lfi_risk",
            "score_flag_exposure_rce_risk",
            "score_flag_exposure_sqli_risk",
            "score_flag_exposure_sensitive_file_exposure",
            "score_flag_exposure_secret_leakage",
            "score_flag_exposure_opsec_debug_log_exposure",
            "score_flag_misconfig_verbose_errors",
            "score_flag_misconfig_cors_allow_all",
            "score_flag_misconfig_chmod_world",
            "score_flag_misconfig_weak_default_creds",
            "score_flag_misconfig_allow_url_include",
            "score_pts_exposure_public_credential_dumps",
            "score_pts_exposure_directory_listing",
            "score_pts_exposure_file_upload_risk",
            "score_pts_exposure_lfi_risk",
            "score_pts_exposure_rce_risk",
            "score_pts_exposure_sqli_risk",
            "score_pts_exposure_sensitive_file_exposure",
            "score_pts_exposure_secret_leakage",
            "score_pts_exposure_opsec_debug_log_exposure",
            "credential_dump_hits", "credential_dump_confirmed_hits",
            "sensitive_file_hits", "sensitive_file_confirmed_hits",
            "opsec_debug_log_hits", "opsec_debug_log_confirmed_hits",
            "secret_confirmed_hits",
            "dir_listing_kit_controlled_hits", "dir_listing_server_wide_hint_hits",
            "attacker_info_public_confirmed_hits",
            "temp_probe_confirmed_hits", "temp_probe_hits",
            "dir_listing_hits", "lfi_hits", "lfi_potential_hits", "rce_hits", "rce_potential_hits",
            "sqli_hits", "sqli_potential_hits", "secret_hits", "live_probe_hits",
            "attacker_cred_collect_hits", "attacker_exfil_mail_hits", "attacker_local_dump_hits",
            "misconfig_verbose_hits", "misconfig_cors_hits", "misconfig_chmod_hits",
            "misconfig_weak_creds_hits", "misconfig_allow_url_include_hits",
        ])
        for r in results:
            eh = r["exposure_hits"]
            ah = r.get("attacker_logic_hits", {})
            sp = r.get("site_profile", {}) or {}

            f_ex_dump = bool(eh["public_credential_dumps"])
            f_ex_dir = bool(eh["directory_listing_suspected"])
            f_ex_upload = bool(eh["file_upload_risk"])
            f_ex_lfi = bool(eh["lfi_risk"])
            f_ex_rce = bool(eh["rce_risk"])
            f_ex_sqli = bool(eh["sqli_risk"])
            f_ex_sensitive = bool(eh["sensitive_file_exposure"])
            f_ex_secret = bool(eh["secret_leakage"])
            f_ex_opsec = bool(eh.get("opsec_debug_log_exposure"))

            mh = r.get("misconfig_hits", {}) or {}
            f_m_verbose = bool(mh.get("verbose_error_disclosure"))
            f_m_cors = bool(mh.get("cors_allow_all"))
            f_m_chmod = bool(mh.get("world_writable_chmod"))
            f_m_weak = bool(mh.get("weak_default_credential_hints"))
            f_m_urlinc = bool(mh.get("allow_url_include_on"))

            p_ex_dump = 3 if f_ex_dump else 0
            p_ex_dir = 2 if f_ex_dir else 0
            p_ex_upload = 2 if f_ex_upload else 0
            p_ex_lfi = 2 if f_ex_lfi else 0
            p_ex_rce = 3 if f_ex_rce else 0
            p_ex_sqli = 2 if f_ex_sqli else 0
            p_ex_sensitive = 2 if f_ex_sensitive else 0
            p_ex_secret = 3 if f_ex_secret else 0
            p_ex_opsec = 2 if f_ex_opsec else 0

            w.writerow([
                safe_text(r["kit_name"]), r["file_count"], r["html_count"], r["css_count"], r["php_count"],
                r["exposure_score"], r.get("misconfig_score", 0), r.get("combined_backend_risk_score", 0),
                r["exposure_suspected"],
                bool(r.get("exposure_real_confirmed")),
                bool(r.get("exposure_policy_confirmed")),
                bool(r.get("exposure_confirmed")),
                bool(r.get("exposure_policy_confirmed_kit_only")),
                bool(r.get("exposure_policy_environmental_only")),
                bool(r.get("exposure_confirmed_kit_only")),
                bool(r.get("is_compromised_legit_snapshot")),
                bool(r.get("post_compromise_injection_evidence")),
                safe_text(sp.get("cms", "")),
                len(sp.get("wordpress_structural_hits", [])),
                len(sp.get("wordpress_operational_log_hits", [])),
                len(sp.get("wordpress_injection_evidence", [])),
                f_ex_dump, f_ex_dir, f_ex_upload, f_ex_lfi, f_ex_rce, f_ex_sqli, f_ex_sensitive, f_ex_secret, f_ex_opsec,
                f_m_verbose, f_m_cors, f_m_chmod, f_m_weak, f_m_urlinc,
                p_ex_dump, p_ex_dir, p_ex_upload, p_ex_lfi, p_ex_rce, p_ex_sqli, p_ex_sensitive, p_ex_secret, p_ex_opsec,
                len(eh["public_credential_dumps"]), len(eh.get("public_credential_dumps_confirmed", [])),
                len(eh["sensitive_file_exposure"]), len(eh.get("sensitive_file_exposure_confirmed", [])),
                len(eh.get("opsec_debug_log_exposure", [])), len(eh.get("opsec_debug_log_exposure_confirmed", [])),
                len(eh.get("secret_leakage_confirmed", [])),
                len(eh.get("directory_listing_kit_controlled", [])),
                len(eh.get("directory_listing_server_wide_hint", [])),
                len(eh.get("attacker_info_public_exposure_confirmed", [])),
                len(eh.get("policy_exposure_temp_probe_confirmed", [])),
                len(eh.get("temp_probe_results", [])),
                len(eh["directory_listing_suspected"]),
                len(eh["lfi_risk"]), len(eh.get("lfi_potential", [])),
                len(eh["rce_risk"]), len(eh.get("rce_potential", [])),
                len(eh["sqli_risk"]), len(eh.get("sqli_potential", [])),
                len(eh["secret_leakage"]), len(eh.get("live_probe_results", [])),
                len(ah.get("credential_collection", [])),
                len(ah.get("exfil_mail", [])),
                len(ah.get("local_dump_write", [])),
                len(mh.get("verbose_error_disclosure", [])),
                len(mh.get("cors_allow_all", [])),
                len(mh.get("world_writable_chmod", [])),
                len(mh.get("weak_default_credential_hints", [])),
                len(mh.get("allow_url_include_on", [])),
            ])


def save_suspected_csv(results: List[Dict], out_csv: str) -> None:
    """Save kits where exposure_suspected OR misconfig_suspected OR combined risk is high."""
    filtered = [
        r for r in results
        if r.get("exposure_suspected")
        or r.get("misconfig_suspected")
    ]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "kit_name",
            "exposure_suspected",
            "exposure_score",
            "exposure_real_confirmed",
            "exposure_policy_confirmed",
            "exposure_policy_confirmed_kit_only",
            "exposure_policy_environmental_only",
            "exposure_confirmed",
            "exposure_confirmed_kit_only",
            "is_compromised_legit_snapshot",
            "post_compromise_injection_evidence",
            "exposure_hit_count",
            "misconfig_score",
            "misconfig_suspected",
            "combined_backend_risk_score",
            "why_flagged",
        ])
        for r in filtered:
            eh = r.get("exposure_hits", {})
            exposure_hit_count = sum(
                len(v) for k, v in eh.items() if isinstance(v, list)
            )
            reasons = []
            if r.get("exposure_suspected"):
                reasons.append("exposure")
            if r.get("misconfig_suspected"):
                reasons.append("misconfig")
            w.writerow([
                safe_text(r.get("kit_name", "")),
                bool(r.get("exposure_suspected")),
                r.get("exposure_score", 0),
                bool(r.get("exposure_real_confirmed")),
                bool(r.get("exposure_policy_confirmed")),
                bool(r.get("exposure_policy_confirmed_kit_only")),
                bool(r.get("exposure_policy_environmental_only")),
                bool(r.get("exposure_confirmed")),
                bool(r.get("exposure_confirmed_kit_only")),
                bool(r.get("is_compromised_legit_snapshot")),
                bool(r.get("post_compromise_injection_evidence")),
                exposure_hit_count,
                r.get("misconfig_score", 0),
                bool(r.get("misconfig_suspected")),
                r.get("combined_backend_risk_score", 0),
                "+".join(reasons),
            ])


def main():
    ap = argparse.ArgumentParser(
        description="Hunt phishing kit trees for exposure, PHP misconfig, and injection sinks (updated)"
    )
    ap.add_argument("--dataset", required=True, help="Dataset root directory")
    ap.add_argument("--skip", type=int, default=0, help="Skip the first N kits (for resume)")
    ap.add_argument("--num", type=int, default=0, help="Analyze first N kits only (0=all)")
    ap.add_argument("--web-root", default="", help="Web root for optional live directory-listing checks")
    ap.add_argument("--base-url", default="", help="Base URL for optional live directory-listing checks")
    ap.add_argument("--live-file-check", action="store_true",
                    help="Actively probe candidate dump/sensitive files over HTTP to confirm open access")
    ap.add_argument("--max-file-probes", type=int, default=40,
                    help="Max candidate files to probe per kit when --live-file-check is enabled")
    ap.add_argument("--temp-probe-create", action="store_true",
                    help="Create temporary .txt/.log/.csv files and verify policy-level HTTP accessibility")
    ap.add_argument("--max-temp-probes", type=int, default=12,
                    help="Max temporary probe files per kit when --temp-probe-create is enabled")
    ap.add_argument("--json-out", default="hunt_results_updated.json", help="Output JSON path")
    ap.add_argument("--csv-out", default="hunt_results_updated.csv", help="Output CSV path")
    ap.add_argument("--suspected-csv-out", default="hunt_suspected_only_updated.csv",
                    help="Output CSV for kits with exposure_suspected OR misconfig_suspected")
    args = ap.parse_args()

    kits = discover_kits(args.dataset)
    if args.skip > 0:
        kits = kits[args.skip:]
    if args.num > 0:
        kits = kits[:args.num]

    print("[Hunt] Kits to analyze:", len(kits))
    results = []
    for i, kit in enumerate(kits, 1):
        print("[Hunt] (%d/%d) %s" % (i, len(kits), safe_text(os.path.basename(kit))))
        results.append(
            analyze_kit(
                kit,
                web_root=args.web_root,
                base_url=args.base_url,
                live_file_check=args.live_file_check,
                max_file_probes=args.max_file_probes,
                temp_probe_create=args.temp_probe_create,
                max_temp_probes=args.max_temp_probes,
            )
        )

    results = sanitize_obj(results)
    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    save_csv(results, args.csv_out)
    save_suspected_csv(results, args.suspected_csv_out)

    exposure_hits = [r for r in results if r["exposure_suspected"]]
    misconfig_hits = [r for r in results if r.get("misconfig_suspected")]
    print("[Hunt] Done.")
    print("[Hunt] Exposure-suspected kits:", len(exposure_hits))
    print("[Hunt] Misconfig-suspected kits:", len(misconfig_hits))
    print("[Hunt] JSON:", args.json_out)
    print("[Hunt] CSV :", args.csv_out)
    print("[Hunt!] Suspected-only CSV :", args.suspected_csv_out)


if __name__ == "__main__":
    main()