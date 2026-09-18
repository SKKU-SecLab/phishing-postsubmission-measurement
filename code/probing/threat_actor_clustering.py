#!/usr/bin/env python3
"""
threat_actor_clustering.py
Phishing kit threat-actor fingerprinting & campaign clustering.

Extracts deterministic forensic artifacts (email, Telegram, git author, SMTP)
that attackers inadvertently expose through OpSec failures, then clusters kits
that share any artifact into campaigns via Union-Find.

Artifact sources (in priority order):
  1. analysis_results_*.json   -- dynamic+static exfil actions (email, telegram)
  2. hunt_results.json         -- exfil_mail code snippets (email, SMTP)
  3. Kit PHP files directly    -- catch anything missed above
  4. .git/logs/HEAD            -- git author name + email

Usage:
  python3 threat_actor_clustering.py \\
    --results-dir  results/dynamic_analysis_blackwidow/analysis_results \\
    --kit-base-dir /path/to/phishing_kits \\
    --hunt-results results/probing/hunt_results.json \\
    --out-dir      results/probing

  # hunt-results is optional; kit-base-dir is optional (skips PHP/git scan)
"""

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

EMAIL_RE        = re.compile(r"[\w.+\-]{2,}@[\w.\-]{2,}\.[a-z]{2,}", re.I)
TG_TOKEN_RE     = re.compile(r"bot(\d{5,12}:[A-Za-z0-9_\-]{20,50})", re.I)
TG_CHAT_RE      = re.compile(r"chat_id=(-?\d{4,15})", re.I)
TG_BOT_ID_RE    = re.compile(r"(\d{5,12}):[A-Za-z0-9_\-]{20,50}")
SMTP_HOST_RE    = re.compile(r"""(?:Host|SMTPHost|smtp_host)\s*[=\>]\s*['"]([^'"]{4,})['"]""", re.I)
SMTP_USER_RE    = re.compile(r"""(?:Username|SMTPUser|smtp_user|Username)\s*[=\>]\s*['"]([^'"@]{2,}@[^'"]{4,})['"]""", re.I)
EMAIL_STRONG_CONTEXT_RE = re.compile(
    r"\b(?:mail\s*\(|@?mail\s*\(|smtp|sendmail|telegram|sendmessage|chat_id|curl|webhook|exfil|recipient)\b"
    r"|(?:new\s+PHPMailer|->(?:addAddress|setFrom|addBCC|addCC))",
    re.I,
)

# PHPDoc / JSDoc @author annotation -- these are library/developer metadata, not attacker IDs
PHPDOC_AUTHOR_RE = re.compile(r"[\*/]\s*@author\b", re.I)

# PHP string assignment heuristic for mail targets
PHP_MAIL_TO_RE  = re.compile(
    r"""(?:mail|@mail)\s*\(\s*\$?\w*\s*,|"""
    r"""to\s*[=\>]+\s*['"]([^'"]{5,})['"]""",
    re.I,
)

# Domains to ignore in email extraction (test/placeholder/framework)
_IGNORE_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.test", "localhost",
    "domain.com", "yourdomain.com", "email.com", "site.invalid",
    "wordpress.org", "php.net", "w3.org", "schema.org",
    "jquery.com", "jquery.org", "getbootstrap.com", "fontawesome.com",
    "zufall.de",       # placeholder in some PHP boilerplates (reiner@zufall.de)
    "satooshi.jp",     # php-jwt library author (author@satooshi.jp)
    "qux.com",         # baz@qux.com -- placeholder
    "phpunit.de",      # PHPUnit team
    "sebastian-bergmann.de",
}

_LIBRARY_EMAIL_DOMAINS = {
    "laravel.com",
    "synchromedia.co.uk",
    "users.sourceforge.net",
    "geoplugin.com",
    "corephp.co.uk",
    "namepros.com",
    "ubermetrics-technologies.com",
    "arduino.com",
    "infegy.com",
    "qvister.se",
    "controllerweb.com.br",
    "stokkebro.dk",
    "setpro.pl",
    "vinades.vn",
    "moz.com",
    "mxtoolbox.com",
}

# Keywords in the full email address that indicate placeholder/library
_IGNORE_EMAIL_KEYWORDS = {
    "noreply", "no-reply", "postmaster", "webmaster",
    "xxxxxxxxxx",          # xxxxxxxxxx@gmail.com placeholder
    "john.doe", "jane.doe",
    "foo@", "bar@", "baz@",
    "user@test", "admin@example", "test@test",
    "reiner@",
}

# Exact email addresses that are definitively library/framework metadata.
# These are extracted from open-source project composer.json "authors" arrays
# and PHPDoc @author annotations bundled inside phishing kits.
_IGNORE_EMAIL_ADDRESSES: frozenset = frozenset({
    # PHPMailer core authors & contributors
    # (appear in src/PHPMailer.php @author tags and composer.json)
    "jimjag@gmail.com",
    "phpmailer@synchromedia.co.uk",
    "codeworxtech@users.sourceforge.net",
    "rich@corephp.co.uk",
    "blaz@orazem.si",
    "fabiobeneditto@gmail.com",
    "info@setpro.pl",
    "info@stokkebro.dk",
    "mail@ianmustafa.com",
    "paulo@controllerweb.com.br",
    "phelipealvesdesouza@gmail.com",
    "xcojad@gmail.com",
    # PHPMailer GitHub contributors listed in CHANGELOG/CONTRIBUTORS
    # (all confirmed from cluster-0 false-positive analysis)
    "liqwei@liqwei.com",
    "brain79@inwind.it",
    "alex@chumakov.ru",
    "bahjat983@hotmail.com",
    "johan@linner.biz",
    "hrvoj3e@gmail.com",
    "matt.sturdy@gmail.com",
    "jaza.ali@gmail.com",
    "amato0617@gmail.com",
    "donatorouco@gmail.com",
    "hrayr@bits.am",
    "mialygk@gmail.com",
    "cecep.prawiro@gmail.com",
    "dk@sum.lt",
    "nawawi@rutweb.com",
    "sabas88@gmail.com",
    "ajevremovic@gmail.com",
    "team@tuxion.nl",
    "boris@yurchenko.pp.ua",
    "yrudyy@prs.net.ua",
    "glen@delfi.ee",
    "ronny@hoojima.com",
    "i18n@forstwoof.ru",
    "masxy@foxmail.com",
    "michaltinka@gmail.com",
    "jonadabe@hotmail.com",
    "mhm5000@gmail.com",
    "techouse@gmail.com",
    "lucas@lucasguimaraes.com",
    "akalongman@gmail.com",
    "ermin@islamagic.com",
    "mr.karanke@gmail.com",
    "alecz.fia@gmail.com",
    "manu@sprain.ch",
    "mmilanovic016@gmail.com",
    "pcmanik91@gmail.com",
    "piyushjha8164@gmail.com",
    "projects@filips.si",
    "eidoriantan@gmail.com",
    "jms@iwb.dk",
    "mrsmakg5@gmail.com",
    "mrmakg6@gmail.com",
    # Smarty template engine mailing list
    "smarty-discussion-subscribe@googlegroups.com",
    # HYIP Manager / FME store template defaults
    "-femail@storeaddress.com",
    # Generic placeholders not caught by keyword filter
    "xyz@gmail.com",
    "dev@gmail.com",
    "youremail@gmail.com",
    "your@gmail.com",
    "putyouremailhere@yandex.com",
    "money@makers.com",
})

_WEAK_EMAIL_DOMAINS = {
    "eg.com",
    "fb.com",
    "mail.com",
    "managewp.com",
    "submerchantemail.com",
    "test.anet.net",
    "wire.com",
}

_WEAK_EMAIL_LOCALS = {
    "admin", "info", "support", "contact", "mail", "root",
    "joe", "ccc", "consumername", "email", "customerone", ".customerone",
}

_WEAK_EMAIL_KEYWORDS = {
    "sample", "example", "demo", "dummy", "placeholder",
    "merchantemail", "customerone", "sprite", "asset", "icon",
}


def normalize_email(addr: str) -> str:
    return addr.strip().strip(".,;:'\"()[]{}<>").lower()


def classify_email(addr: str) -> str:
    """
    Classify an extracted email-like value.

    strong: plausible actor/exfil identifier.
    weak:   template/sample/library clue. Useful for kit fingerprinting, but
            weaker than actor identifiers for campaign attribution.
    ignore: too generic/noisy to retain.
    """
    addr = normalize_email(addr)
    if "@" not in addr or len(addr) > 120:
        return "ignore"

    local, domain = addr.rsplit("@", 1)
    if not local or not domain or len(domain) > 60:
        return "ignore"
    domain_parts = domain.split(".")
    if len(domain_parts) < 2:
        return "ignore"
    if domain_parts[-1] in {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js"}:
        return "ignore"
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return "weak"
    # Exact-address blocklist: known library authors / placeholder emails
    if addr in _IGNORE_EMAIL_ADDRESSES:
        return "ignore"
    if domain in _IGNORE_EMAIL_DOMAINS:
        return "ignore"
    if domain in _LIBRARY_EMAIL_DOMAINS:
        return "weak"
    if any(kw in addr for kw in _IGNORE_EMAIL_KEYWORDS):
        return "ignore"
    if re.fullmatch(r"[\d.]+", local):
        return "ignore"
    if re.search(r"(^|\.)test\.", domain) or domain.startswith("test."):
        return "weak"
    if domain in _WEAK_EMAIL_DOMAINS or local in _WEAK_EMAIL_LOCALS:
        return "weak"
    if any(kw in addr for kw in _WEAK_EMAIL_KEYWORDS):
        return "weak"
    return "strong"


def is_valid_attacker_email(addr: str) -> bool:
    return classify_email(addr) == "strong"


def add_email_artifact(addr: str, artifacts: Dict, force_weak: bool = False) -> Optional[str]:
    addr = normalize_email(addr)
    confidence = classify_email(addr)
    if force_weak and confidence == "strong":
        confidence = "weak"
    if confidence == "strong":
        artifacts["email"].add(addr)
        artifacts["weak_email"].discard(addr)
    elif confidence == "weak":
        if addr not in artifacts["email"]:
            artifacts["weak_email"].add(addr)
    return confidence if confidence != "ignore" else None


def add_php_context_emails(
    content: str,
    artifacts: Dict,
    library_emails: Optional[Set] = None,
) -> None:
    """Promote only emails near exfil/SMTP/Telegram code to strong candidates.

    Skips PHPDoc @author lines -- those are library/developer metadata, not
    attacker exfil addresses.  Also skips any address present in library_emails
    (populated from composer.json author fields found in the same kit).
    """
    lines = content.splitlines()
    for idx, line in enumerate(lines):
        if not EMAIL_STRONG_CONTEXT_RE.search(line):
            continue
        start = max(0, idx - 2)
        end = min(len(lines), idx + 3)
        for ctx_line in lines[start:end]:
            # @author PHPDoc annotations are library metadata -- leave as weak
            if PHPDOC_AUTHOR_RE.search(ctx_line):
                for addr in EMAIL_RE.findall(ctx_line):
                    add_email_artifact(addr, artifacts, force_weak=True)
                continue
            for addr in EMAIL_RE.findall(ctx_line):
                if library_emails and normalize_email(addr) in library_emails:
                    continue
                add_email_artifact(addr, artifacts)


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------

class UnionFind:
    def __init__(self):
        self._parent: Dict[str, str] = {}
        self._rank:   Dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x]   = 0
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1

    def groups(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = defaultdict(list)
        for node in self._parent:
            out[self.find(node)].append(node)
        return dict(out)


# ---------------------------------------------------------------------------
# Artifact extraction helpers
# ---------------------------------------------------------------------------

def extract_from_action_target(target: str, artifacts: Dict):
    """Parse a single action.target string for email/telegram artifacts."""
    if not target:
        return

    # Emails from action targets are already exfil context.
    for addr in EMAIL_RE.findall(target):
        add_email_artifact(addr, artifacts)

    # Telegram token + chat_id
    for m in TG_TOKEN_RE.finditer(target):
        full_token = m.group(1)
        bot_id     = full_token.split(":")[0]
        artifacts["telegram_token"].add(full_token)
        artifacts["telegram_bot"].add(bot_id)

    for m in TG_CHAT_RE.finditer(target):
        cid = m.group(1)
        if abs(int(cid)) > 1000:            # filter out tiny numbers
            artifacts["telegram_chat"].add(cid)

    # Bare bot token without /sendMessage context (e.g. "1234567:AABB...")
    for m in TG_BOT_ID_RE.finditer(target):
        artifacts["telegram_bot"].add(m.group(1))


def extract_from_php_file(
    path: str,
    artifacts: Dict,
    max_file_size: int,
    library_emails: Optional[Set] = None,
) -> bool:
    """Scan a single PHP file for all artifact types."""
    try:
        if max_file_size > 0 and os.path.getsize(path) > max_file_size:
            artifacts["_skipped_large_files"].add(path)
            return False
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    # Whole-file emails are template/library clues unless they appear near
    # exfil/SMTP/Telegram code below.
    for addr in EMAIL_RE.findall(content):
        add_email_artifact(addr, artifacts, force_weak=True)
    add_php_context_emails(content, artifacts, library_emails=library_emails)

    # Telegram tokens and chat IDs
    for m in TG_TOKEN_RE.finditer(content):
        full_token = m.group(1)
        bot_id     = full_token.split(":")[0]
        artifacts["telegram_token"].add(full_token)
        artifacts["telegram_bot"].add(bot_id)
    for m in TG_CHAT_RE.finditer(content):
        cid = m.group(1)
        if abs(int(cid)) > 1000:
            artifacts["telegram_chat"].add(cid)

    # SMTP credentials (PHPMailer-style)
    for m in SMTP_HOST_RE.finditer(content):
        host = m.group(1).strip()
        if "." in host and len(host) < 80:
            artifacts["smtp_host"].add(host.lower())
    for m in SMTP_USER_RE.finditer(content):
        user = m.group(1).strip()
        confidence = add_email_artifact(user, artifacts)
        if confidence == "strong":
            artifacts["smtp_user"].add(normalize_email(user))
    return True


def normalize_git_remote_url(url: str) -> Optional[str]:
    """Normalize common HTTPS/SSH/scp-style git remotes for clustering."""
    url = url.strip().strip("'\"")
    if not url or len(url) > 300:
        return None
    url = re.sub(r"^git\+", "", url, flags=re.I)

    scp_m = re.match(r"(?:[^@/\s]+@)?([^:/\s]+):(.+)$", url)
    if scp_m and "://" not in url:
        host = scp_m.group(1).lower()
        path = scp_m.group(2).strip("/")
    else:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.strip("/")
        if not host or not path:
            return None

    path = re.sub(r"\.git$", "", path, flags=re.I)
    path = re.sub(r"/+", "/", path)
    if not path or path in (".", "/"):
        return None
    return f"{host}/{path.lower()}"


def add_git_remote(url: str, artifacts: Dict) -> None:
    normalized = normalize_git_remote_url(url)
    if not normalized:
        return
    artifacts["git_remote_url"].add(normalized)
    parts = normalized.split("/")
    if len(parts) >= 2:
        host, owner = parts[0], parts[1]
        if owner:
            artifacts["git_remote_owner"].add(f"{host}/{owner}")
    if len(parts) >= 3:
        artifacts["git_remote_repo"].add("/".join(parts[:3]))


def add_git_author(name: str, email: str, artifacts: Dict) -> None:
    name = (name or "").strip()
    email = normalize_email(email or "")
    if name and len(name) > 1:
        artifacts["git_author_name"].add(name)
    if email and "@" in email and add_email_artifact(email, artifacts) == "strong":
        artifacts["git_author_email"].add(email)


def extract_git_metadata(git_dir: str, artifacts: Dict, kit_dir: Optional[str] = None) -> bool:
    """Extract lightweight forensic artifacts from one exposed .git directory."""
    if not os.path.isdir(git_dir):
        return False

    if kit_dir:
        try:
            artifacts["git_paths"].add(os.path.relpath(git_dir, kit_dir))
        except Exception:
            artifacts["git_paths"].add(git_dir)

    # Reflog format: <oldsha> <newsha> Name <email> <timestamp> <tz>\t<msg>
    author_re = re.compile(r"^[0-9a-f]{40}\s+[0-9a-f]{40}\s+(.+?) <([^>]+)> \d+ ", re.I)
    logs_dir = os.path.join(git_dir, "logs")
    if os.path.isdir(logs_dir):
        for root, dirs, files in os.walk(logs_dir):
            depth = root[len(logs_dir):].count(os.sep)
            if depth > 5:
                dirs.clear()
                continue
            for fname in files:
                log_path = os.path.join(root, fname)
                try:
                    if os.path.getsize(log_path) > 2 * 1024 * 1024:
                        continue
                    with open(log_path, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            m = author_re.search(line)
                            if m:
                                add_git_author(m.group(1), m.group(2), artifacts)
                except Exception:
                    continue

    # Small metadata files may expose remotes, branch names, emails, or GitHub IDs.
    metadata_files = [
        "config",
        "FETCH_HEAD",
        "COMMIT_EDITMSG",
        "MERGE_MSG",
        "packed-refs",
    ]
    url_re = re.compile(
        r"(?:https?|git|ssh)://[^\s'\"<>]+|(?:git@|ssh://git@)?[A-Za-z0-9_.-]+\.[A-Za-z]{2,}:[^\s'\"<>]+",
        re.I,
    )
    config_url_re = re.compile(r"^\s*url\s*=\s*(.+?)\s*$", re.I | re.M)
    for rel_path in metadata_files:
        path = os.path.join(git_dir, rel_path)
        if not os.path.isfile(path):
            continue
        try:
            if os.path.getsize(path) > 2 * 1024 * 1024:
                continue
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for m in config_url_re.finditer(text):
            add_git_remote(m.group(1), artifacts)
        for m in url_re.finditer(text):
            add_git_remote(m.group(0), artifacts)
        for addr in EMAIL_RE.findall(text):
            confidence = add_email_artifact(addr, artifacts)
            if confidence == "strong":
                artifacts["git_author_email"].add(normalize_email(addr))
    return True


def discover_git_dirs(kit_dir: str, max_depth: int = 8, max_git_dirs: int = 25) -> List[str]:
    """Find exposed .git directories anywhere under a kit, with bounded traversal."""
    found: List[str] = []
    skip_dirs = {
        ".svn", ".hg", "vendor", "node_modules", "__pycache__",
        "wp-includes", "wp-admin", "xampp", "phpmyadmin", "phpMyAdmin",
        "symfony", "doctrine", "laravel", "joomla", "drupal", "magento",
        "tests", "test", "docs", "doc", "documentation",
    }

    for root, dirs, _files in os.walk(kit_dir):
        depth = root[len(kit_dir):].count(os.sep)
        if depth > max_depth:
            dirs.clear()
            continue
        if ".git" in dirs:
            found.append(os.path.join(root, ".git"))
            dirs[:] = [d for d in dirs if d != ".git"]
            if len(found) >= max_git_dirs:
                break
        dirs[:] = [d for d in dirs if d not in skip_dirs]
    return found


def extract_git_info(kit_dir: str, artifacts: Dict) -> int:
    """Extract git artifacts from root and nested exposed .git directories."""
    count = 0
    seen: Set[str] = set()
    for git_dir in discover_git_dirs(kit_dir):
        real = os.path.abspath(git_dir)
        if real in seen:
            continue
        seen.add(real)
        if extract_git_metadata(git_dir, artifacts, kit_dir=kit_dir):
            count += 1
    return count


def read_composer_library_emails(kit_dir: str) -> Set[str]:
    """Collect author emails declared in composer.json library packages.

    A composer.json with "name": "vendor/package" (contains a slash) is a
    published library bundled inside the kit -- its "authors" emails are
    developer metadata, not attacker identifiers.  We scan the kit root and
    one directory level deep to catch libraries dropped directly into the kit
    folder (not inside vendor/, which is already skipped).
    """
    found: Set[str] = set()

    def _ingest(path: str) -> None:
        try:
            if os.path.getsize(path) > 256 * 1024:
                return
            with open(path, encoding="utf-8", errors="ignore") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                return
            # Only treat as a library if it carries a vendor/package name
            if "/" not in data.get("name", ""):
                return
            for author in data.get("authors") or []:
                if not isinstance(author, dict):
                    continue
                email = (author.get("email") or "").strip().lower()
                if email and "@" in email:
                    found.add(email)
        except Exception:
            pass

    # Root-level composer.json (kit IS a library, e.g. 2022-07-05_phpmailer)
    _ingest(os.path.join(kit_dir, "composer.json"))

    # One level deep: library dropped as a top-level subfolder
    try:
        for entry in os.listdir(kit_dir):
            sub = os.path.join(kit_dir, entry, "composer.json")
            if os.path.isfile(sub):
                _ingest(sub)
    except Exception:
        pass

    return found


def scan_kit_directory(
    kit_dir: str,
    artifacts: Dict,
    max_file_size: int,
    max_files_per_kit: int,
    kit_timeout_seconds: int,
) -> Dict[str, int]:
    """Walk kit directory, scan PHP files and .git/ for artifacts."""
    stats = {
        "files_scanned": 0,
        "files_skipped_large": 0,
        "files_skipped_limit": 0,
        "timed_out": 0,
        "git_dirs_scanned": 0,
    }
    if not os.path.isdir(kit_dir):
        return stats

    stats["git_dirs_scanned"] = extract_git_info(kit_dir, artifacts)

    # Collect library author emails from composer.json before scanning PHP files.
    # These are used to suppress false-positive strong-email promotions that arise
    # when open-source libraries (e.g. PHPMailer) are bundled inside a phishing kit.
    library_emails = read_composer_library_emails(kit_dir)

    php_exts = {".php", ".phtml", ".php5", ".php7", ".inc"}
    start = time.monotonic()
    for root, dirs, files in os.walk(kit_dir):
        if kit_timeout_seconds > 0 and time.monotonic() - start > kit_timeout_seconds:
            dirs.clear()
            stats["timed_out"] = 1
            break
        # Skip deep paths (framework libraries generate noise)
        depth = root[len(kit_dir):].count(os.sep)
        if depth > 6:
            dirs.clear()
            continue
        # Skip known large framework / CMS / tool directories (noise + speed)
        _SKIP_DIRS = {
            # version control
            ".git", ".svn", ".hg",
            # PHP package managers
            "vendor", "composer",
            # JS
            "node_modules",
            # WordPress core (kit might bundle a full WP copy)
            "wp-includes", "wp-admin", "wp-content",
            # XAMPP and embedded server stacks
            "xampp", "htdocs", "phpmyadmin", "phpMyAdmin",
            "apache", "mysql", "perl", "php", "sendmail",
            # Common large frameworks bundled in some kits
            "symfony", "doctrine", "twig", "monolog",
            "illuminate", "laravel", "zend", "yii",
            "joomla", "drupal", "magento", "opencart",
            "dolibarr", "htdocs",
            # Dev tooling
            "__pycache__", ".idea", ".vscode",
            "test", "tests", "spec",
            "examples", "example", "demo", "demos",
            "docs", "doc", "documentation",
        }
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if kit_timeout_seconds > 0 and time.monotonic() - start > kit_timeout_seconds:
                stats["timed_out"] = 1
                break
            if any(fname.lower().endswith(e) for e in php_exts):
                if max_files_per_kit > 0 and stats["files_scanned"] >= max_files_per_kit:
                    stats["files_skipped_limit"] += 1
                    dirs.clear()
                    break
                before_large = len(artifacts.get("_skipped_large_files", set()))
                scanned = extract_from_php_file(
                    os.path.join(root, fname),
                    artifacts,
                    max_file_size=max_file_size,
                    library_emails=library_emails,
                )
                after_large = len(artifacts.get("_skipped_large_files", set()))
                if after_large > before_large:
                    stats["files_skipped_large"] += 1
                if scanned:
                    stats["files_scanned"] += 1
        if stats["timed_out"] or (
            max_files_per_kit > 0 and stats["files_scanned"] >= max_files_per_kit
        ):
            break
    return stats


# ---------------------------------------------------------------------------
# Source 1: analysis_results JSON files
# ---------------------------------------------------------------------------

def iter_result_files(results_dir: str):
    for name in sorted(os.listdir(results_dir)):
        if name.startswith("analysis_results_") and name.endswith(".json"):
            yield os.path.join(results_dir, name)


def extract_kit_name(data: dict, filepath: str) -> str:
    kit_path = data.get("kit_path") or ""
    if kit_path:
        parts = re.split(r"[/\\]", kit_path.rstrip("/\\"))
        date_part = next(
            (p for p in reversed(parts) if re.search(r"\d{4}-\d{2}-\d{2}", p)), None
        )
        return date_part if date_part else (parts[-1] if parts else "")
    base = os.path.basename(filepath)
    stem = base[:-5] if base.endswith(".json") else base
    if stem.startswith("analysis_results_"):
        stem = stem[len("analysis_results_"):]
    m = re.search(r"_(\d+\.\d+|\d+)$", stem)
    return stem[:m.start()] if m else stem


def load_from_analysis_results(results_dir: str) -> Dict[str, Dict[str, Set]]:
    """Build kit_name -> artifact_sets from analysis_results JSON files."""
    kit_artifacts: Dict[str, Dict[str, Set]] = {}

    for fp in iter_result_files(results_dir):
        try:
            with open(fp, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        kit_name = extract_kit_name(data, fp)
        arts = kit_artifacts.setdefault(kit_name, _empty_artifacts())

        for form in (data.get("forms") or []):
            # Static actions
            saa = form.get("static_action_analysis") or {}
            for act in (saa.get("actions") or []):
                extract_from_action_target(act.get("target") or "", arts)
            for exfil in (saa.get("exfil") or []):
                extract_from_action_target(exfil, arts)

            # Dynamic resolved_server actions
            submit_log = form.get("submit_log") or {}
            submit_click = submit_log.get("submit_click_logs") or {}
            for req in (submit_click.get("networkReqs") or []):
                resolved = req.get("resolved_server") or {}
                for act in (resolved.get("actions") or []):
                    extract_from_action_target(act.get("target") or "", arts)
                for exfil in (resolved.get("exfil") or []):
                    extract_from_action_target(exfil, arts)

    return kit_artifacts


# ---------------------------------------------------------------------------
# Source 2: hunt_results.json
# ---------------------------------------------------------------------------

def load_from_hunt_results(hunt_path: str, kit_artifacts: Dict[str, Dict[str, Set]]) -> None:
    """Supplement artifacts from hunt_results.json exfil_mail code snippets."""
    if not hunt_path or not os.path.isfile(hunt_path):
        return

    try:
        with open(hunt_path, encoding="utf-8") as f:
            records = json.load(f)
    except Exception:
        return

    if not isinstance(records, list):
        records = list(records.values()) if isinstance(records, dict) else []

    for rec in records:
        kit_name = rec.get("kit_name") or ""
        if not kit_name:
            continue
        arts = kit_artifacts.setdefault(kit_name, _empty_artifacts())

        attacker_hits = rec.get("attacker_logic_hits") or {}
        for snippet in (attacker_hits.get("exfil_mail") or []):
            # snippet: "file.php::line=N pattern=... code=..."
            code_part = snippet.split("code=", 1)[-1] if "code=" in snippet else snippet
            for addr in EMAIL_RE.findall(code_part):
                add_email_artifact(addr, arts)

        # Also check public credential dump filenames (shared naming = same template)
        for dump_entry in (rec.get("exposure_hits", {}).get("public_credential_dumps") or []):
            fname = dump_entry.split("::")[0]
            arts["dump_filename"].add(fname.lower())

        # Kit path for cross-referencing
        kit_path = rec.get("kit_path") or ""
        if kit_path:
            arts["_kit_path"] = kit_path


# ---------------------------------------------------------------------------
# Source 3: Kit PHP + git scan
# ---------------------------------------------------------------------------

def load_from_kit_files(
    kit_base_dir: str,
    kit_artifacts: Dict[str, Dict[str, Set]],
    max_file_size: int,
    max_files_per_kit: int,
    kit_timeout_seconds: int,
    progress_every: int,
) -> None:
    """Scan each kit directory under kit_base_dir."""
    if not kit_base_dir or not os.path.isdir(kit_base_dir):
        return

    kit_dirs = sorted(os.listdir(kit_base_dir))
    total = len(kit_dirs)
    for i, kit_dir_name in enumerate(kit_dirs, 1):
        full_path = os.path.join(kit_base_dir, kit_dir_name)
        if not os.path.isdir(full_path):
            continue
        if progress_every > 0 and (i == 1 or i % progress_every == 0):
            print(f"  [kit scan] {i}/{total}: {kit_dir_name}", file=sys.stderr)
        arts = kit_artifacts.setdefault(kit_dir_name, _empty_artifacts())
        stats = scan_kit_directory(
            full_path,
            arts,
            max_file_size=max_file_size,
            max_files_per_kit=max_files_per_kit,
            kit_timeout_seconds=kit_timeout_seconds,
        )
        arts["_scan_files_scanned"].add(str(stats["files_scanned"]))
        arts["_scan_files_skipped_large"].add(str(stats["files_skipped_large"]))
        arts["_scan_files_skipped_limit"].add(str(stats["files_skipped_limit"]))
        arts["_scan_git_dirs"].add(str(stats["git_dirs_scanned"]))
        if stats["timed_out"]:
            arts["_scan_timed_out"].add("1")
            print(
                f"  [kit scan] timeout skipped after {kit_timeout_seconds}s: {kit_dir_name}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_artifacts() -> Dict[str, Set]:
    return {
        "email":            set(),
        "weak_email":       set(),
        "smtp_user":        set(),
        "smtp_host":        set(),
        "telegram_token":   set(),
        "telegram_bot":     set(),
        "telegram_chat":    set(),
        "git_author_name":  set(),
        "git_author_email": set(),
        "git_remote_url":   set(),
        "git_remote_owner": set(),
        "git_remote_repo":  set(),
        "git_paths":        set(),
        "dump_filename":    set(),
        "_skipped_large_files": set(),
        "_scan_files_scanned": set(),
        "_scan_files_skipped_large": set(),
        "_scan_files_skipped_limit": set(),
        "_scan_timed_out": set(),
        "_scan_git_dirs": set(),
    }


def build_identifier_keys(
    arts: Dict[str, Set],
    include_weak_identifiers: bool = False,
) -> Set[str]:
    """Convert artifact sets into typed identifier strings used for clustering."""
    keys: Set[str] = set()
    for addr in arts.get("email", set()):
        keys.add(f"email:{addr}")
    if include_weak_identifiers:
        for addr in arts.get("weak_email", set()):
            keys.add(f"weak_email:{addr}")
    for bot in arts.get("telegram_bot", set()):
        keys.add(f"tg_bot:{bot}")
    for chat in arts.get("telegram_chat", set()):
        keys.add(f"tg_chat:{chat}")
    for token in arts.get("telegram_token", set()):
        # Use full token -- strongest unique signal
        keys.add(f"tg_token:{token}")
    for name in arts.get("git_author_name", set()):
        if len(name) > 3:                   # skip very short names
            keys.add(f"git_name:{name.lower()}")
    for gemail in arts.get("git_author_email", set()):
        keys.add(f"git_email:{gemail}")
    for url in arts.get("git_remote_url", set()):
        keys.add(f"git_url:{url}")
    for owner in arts.get("git_remote_owner", set()):
        keys.add(f"git_owner:{owner}")
    for repo in arts.get("git_remote_repo", set()):
        keys.add(f"git_repo:{repo}")
    # dump filenames only if attacker-specific (exclude common framework/library files)
    _generic_dumps = {
        # generic log names
        "log.txt", "cc.txt", "result.txt", "data.txt", "pass.txt",
        "output.txt", "save.txt", "info.txt", "logs.txt", "results.txt",
        "stored.txt", "dump.txt", "victims.txt",
        # WordPress / framework files commonly found in kits
        "readme.txt", "readme.md", "changelog.txt", "license.txt",
        "install.txt", "upgrade.txt", "contributing.md", "authors.txt",
        "todo.txt", "changes.txt", "history.txt", "news.txt",
        "copying.txt", "credits.txt",
        # generic temp / config
        "config.txt", "settings.txt", "error.txt", "debug.txt",
        "disposable.txt", "whitelist.txt", "blacklist.txt",
    }
    if include_weak_identifiers:
        for fname in arts.get("dump_filename", set()):
            base = os.path.basename(fname).lower()
            if base in _generic_dumps:
                continue
            if len(base) <= 4:          # too short to be distinctive
                continue
            # skip framework / library files
            if any(kw in base for kw in (
                "materialicons", "license", "changelog", "readme",
                "rfc", "laravel", "symfony", "composer",
            )):
                continue
            keys.add(f"dump:{base}")
    return keys


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------

def cluster(kit_identifiers: Dict[str, Set[str]]) -> Tuple[UnionFind, Dict[str, Set[str]]]:
    """
    Union-Find clustering on kits sharing identifiers.

    Returns:
        uf              : UnionFind instance (query clusters via uf.groups())
        id_to_kits      : identifier -> set of kit names that have it
    """
    id_to_kits: Dict[str, Set[str]] = defaultdict(set)
    for kit_name, ids in kit_identifiers.items():
        for id_key in ids:
            id_to_kits[id_key].add(kit_name)

    uf = UnionFind()
    # Register all kits
    for kit_name in kit_identifiers:
        uf.find(kit_name)

    # Union kits that share an identifier
    for id_key, kits in id_to_kits.items():
        if len(kits) < 2:
            continue              # singleton identifier -- no clustering possible
        kit_list = sorted(kits)
        for i in range(1, len(kit_list)):
            uf.union(kit_list[0], kit_list[i])

    return uf, dict(id_to_kits)


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_csv(path: str, headers: List[str], rows) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def save_outputs(
    out_dir: str,
    kit_identifiers: Dict[str, Set[str]],
    kit_artifacts: Dict[str, Dict[str, Set]],
    uf: UnionFind,
    id_to_kits: Dict[str, Set[str]],
) -> None:
    os.makedirs(out_dir, exist_ok=True)

    groups = uf.groups()

    # Assign deterministic cluster IDs (sorted by size desc, then by earliest kit name)
    sorted_roots = sorted(
        groups.keys(),
        key=lambda r: (-len(groups[r]), sorted(groups[r])[0]),
    )
    root_to_cid = {root: i for i, root in enumerate(sorted_roots)}

    kit_to_cid: Dict[str, int] = {}
    for root, members in groups.items():
        cid = root_to_cid[root]
        for kit in members:
            kit_to_cid[kit] = cid

    # -----------------------------------------------------------------------
    # 1. artifacts.jsonl -- per-kit artifact dump
    # -----------------------------------------------------------------------
    with open(os.path.join(out_dir, "artifacts.jsonl"), "w", encoding="utf-8") as f:
        for kit_name in sorted(kit_artifacts):
            arts = kit_artifacts[kit_name]
            record = {
                "kit_name":     kit_name,
                "cluster_id":   kit_to_cid.get(kit_name, -1),
                "email":        sorted(arts.get("email", set())),
                "weak_email":   sorted(arts.get("weak_email", set())),
                "smtp_user":    sorted(arts.get("smtp_user", set())),
                "telegram_bot": sorted(arts.get("telegram_bot", set())),
                "telegram_chat": sorted(arts.get("telegram_chat", set())),
                "telegram_token": sorted(arts.get("telegram_token", set())),
                "git_author_name":  sorted(arts.get("git_author_name", set())),
                "git_author_email": sorted(arts.get("git_author_email", set())),
                "git_remote_url":   sorted(arts.get("git_remote_url", set())),
                "git_remote_owner": sorted(arts.get("git_remote_owner", set())),
                "git_remote_repo":  sorted(arts.get("git_remote_repo", set())),
                "git_paths":        sorted(arts.get("git_paths", set())),
                "dump_filename":    sorted(arts.get("dump_filename", set())),
                "scan_files_scanned": sorted(arts.get("_scan_files_scanned", set())),
                "scan_files_skipped_large": sorted(arts.get("_scan_files_skipped_large", set())),
                "scan_files_skipped_limit": sorted(arts.get("_scan_files_skipped_limit", set())),
                "scan_git_dirs": sorted(arts.get("_scan_git_dirs", set())),
                "scan_timed_out": sorted(arts.get("_scan_timed_out", set())),
                "identifier_keys":  sorted(kit_identifiers.get(kit_name, set())),
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # -----------------------------------------------------------------------
    # 2. kit_clusters.csv -- one row per kit
    # -----------------------------------------------------------------------
    kit_rows = []
    for kit_name in sorted(kit_artifacts):
        cid = kit_to_cid.get(kit_name, -1)
        members = groups.get(uf.find(kit_name), [kit_name])
        cluster_size = len(members)

        # Shared identifiers: identifiers this kit has that appear in ≥2 kits
        shared_ids = sorted(
            k for k in kit_identifiers.get(kit_name, set())
            if len(id_to_kits.get(k, set())) >= 2
        )
        kit_rows.append([
            kit_name,
            cid,
            cluster_size,
            len(kit_identifiers.get(kit_name, set())),
            len(shared_ids),
            "; ".join(shared_ids[:5]),
        ])

    write_csv(
        os.path.join(out_dir, "kit_clusters.csv"),
        ["kit_name", "cluster_id", "cluster_size",
         "total_identifiers", "shared_identifiers", "shared_id_sample"],
        kit_rows,
    )

    # -----------------------------------------------------------------------
    # 3. cluster_details.csv -- per-cluster identifier breakdown
    # -----------------------------------------------------------------------
    detail_rows = []
    for root in sorted_roots:
        cid = root_to_cid[root]
        members = sorted(groups[root])
        if len(members) < 2:
            continue  # skip singletons in detail report

        # Collect identifiers shared within this cluster
        id_counts: Dict[str, int] = {}
        for kit in members:
            for id_key in kit_identifiers.get(kit, set()):
                kit_count = len(id_to_kits.get(id_key, set()))
                if kit_count >= 2:
                    id_counts[id_key] = kit_count

        for id_key, kit_count in sorted(id_counts.items(), key=lambda x: -x[1]):
            id_type, id_val = id_key.split(":", 1)
            kits_with_id = sorted(id_to_kits.get(id_key, set()))
            detail_rows.append([
                cid,
                len(members),
                "; ".join(members[:8]),
                id_type,
                id_val,
                kit_count,
                "; ".join(kits_with_id[:8]),
            ])

    write_csv(
        os.path.join(out_dir, "cluster_details.csv"),
        ["cluster_id", "cluster_size", "cluster_kits_sample",
         "identifier_type", "identifier_value",
         "kit_count_with_this_id", "kits_with_this_id"],
        detail_rows,
    )

    # -----------------------------------------------------------------------
    # 4. cluster_summary.csv -- one row per cluster (size ≥ 2)
    # -----------------------------------------------------------------------
    summary_rows = []
    for root in sorted_roots:
        cid = root_to_cid[root]
        members = sorted(groups[root])
        if len(members) < 2:
            continue

        # Dominant identifier types in this cluster
        type_counts: Dict[str, int] = defaultdict(int)
        for kit in members:
            for id_key in kit_identifiers.get(kit, set()):
                if len(id_to_kits.get(id_key, set())) >= 2:
                    type_counts[id_key.split(":")[0]] += 1

        dominant_types = "; ".join(
            f"{t}({c})" for t, c in sorted(type_counts.items(), key=lambda x: -x[1])
        )

        # Date range (YYYY-MM-DD prefix of kit names)
        dates = sorted(
            re.search(r"\d{4}-\d{2}-\d{2}", k).group(0)
            for k in members
            if re.search(r"\d{4}-\d{2}-\d{2}", k)
        )
        date_range = f"{dates[0]} ~ {dates[-1]}" if dates else ""

        summary_rows.append([
            cid,
            len(members),
            date_range,
            dominant_types,
            "; ".join(members[:10]),
        ])

    write_csv(
        os.path.join(out_dir, "cluster_summary.csv"),
        ["cluster_id", "cluster_size", "date_range",
         "dominant_identifier_types", "kit_names_sample"],
        summary_rows,
    )

    # -----------------------------------------------------------------------
    # 5. identifier_index.csv -- identifier -> which kits have it (≥2 kits)
    # -----------------------------------------------------------------------
    id_rows = []
    for id_key, kits in sorted(id_to_kits.items(), key=lambda x: -len(x[1])):
        if len(kits) < 2:
            continue
        id_type, id_val = id_key.split(":", 1)
        cids = sorted({kit_to_cid.get(k, -1) for k in kits})
        id_rows.append([
            id_type,
            id_val,
            len(kits),
            "; ".join(str(c) for c in cids),
            "; ".join(sorted(kits)[:10]),
        ])

    write_csv(
        os.path.join(out_dir, "identifier_index.csv"),
        ["identifier_type", "identifier_value",
         "kit_count", "cluster_ids", "kits_sample"],
        id_rows,
    )

    # -----------------------------------------------------------------------
    # 6. Summary JSON
    # -----------------------------------------------------------------------
    non_singleton_clusters = [g for g in groups.values() if len(g) >= 2]
    clustered_kits = sum(len(g) for g in non_singleton_clusters)

    id_type_dist: Dict[str, int] = defaultdict(int)
    for id_key, kits in id_to_kits.items():
        if len(kits) >= 2:
            id_type_dist[id_key.split(":")[0]] += len(kits)

    summary = {
        "total_kits": len(kit_artifacts),
        "kits_with_any_identifier": len(kit_identifiers),
        "kits_clustered_into_campaigns": clustered_kits,
        "singleton_kits": len(kit_artifacts) - clustered_kits,
        "total_clusters": len(groups),
        "multi_kit_clusters": len(non_singleton_clusters),
        "largest_cluster_size": max((len(g) for g in groups.values()), default=0),
        "unique_identifiers_used_for_clustering": len(
            [k for k, v in id_to_kits.items() if len(v) >= 2]
        ),
        "identifier_type_distribution": dict(
            sorted(id_type_dist.items(), key=lambda x: -x[1])
        ),
        "top10_clusters_by_size": [
            {
                "cluster_id": root_to_cid[r],
                "size": len(groups[r]),
                "kits": sorted(groups[r])[:5],
            }
            for r in sorted_roots[:10]
            if len(groups[r]) >= 2
        ],
    }

    with open(os.path.join(out_dir, "clustering_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    return summary


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Phishing kit threat-actor clustering")
    parser.add_argument("--results-dir",  help="Directory of analysis_results_*.json")
    parser.add_argument("--kit-base-dir", help="Root directory of unpacked kits (for PHP/git scan)")
    parser.add_argument("--hunt-results", help="Path to hunt_results.json")
    parser.add_argument("--out-dir",  required=True, help="Output directory for results")
    parser.add_argument(
        "--include-weak-identifiers",
        action="store_true",
        help="Also include template-level clues such as weak_email/dump_filename as clustering keys",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1,
        help="Interval for printing kit-scan progress logs (default: 1 = print for every kit)",
    )
    parser.add_argument(
        "--kit-timeout-seconds",
        type=int,
        default=30,
        help="Abort scanning a kit and move to the next one if it exceeds this time (default: 30s, 0=disabled)",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=512 * 1024,
        help="Do not read PHP files larger than this size (default: 512KiB, 0=disabled)",
    )
    parser.add_argument(
        "--max-files-per-kit",
        type=int,
        default=300,
        help="Upper bound on the number of PHP files read per kit (default: 300, 0=disabled)",
    )
    args = parser.parse_args()

    if not args.results_dir and not args.kit_base_dir and not args.hunt_results:
        parser.error("Specify at least one data source (--results-dir, --kit-base-dir, --hunt-results).")

    kit_artifacts: Dict[str, Dict[str, Set]] = {}

    # Source 1: analysis_results JSON
    if args.results_dir:
        print(f"[1/3] Loading analysis_results JSON: {args.results_dir}", file=sys.stderr)
        loaded = load_from_analysis_results(args.results_dir)
        for k, v in loaded.items():
            a = kit_artifacts.setdefault(k, _empty_artifacts())
            for art_type, vals in v.items():
                a[art_type].update(vals)
        print(f"      -> loaded {len(kit_artifacts)} kits", file=sys.stderr)

    # Source 2: hunt_results.json
    if args.hunt_results:
        print(f"[2/3] Loading hunt_results.json: {args.hunt_results}", file=sys.stderr)
        before = len(kit_artifacts)
        load_from_hunt_results(args.hunt_results, kit_artifacts)
        print(f"      -> added {len(kit_artifacts) - before} kits", file=sys.stderr)

    # Source 3: Kit PHP files + .git
    if args.kit_base_dir:
        print(f"[3/3] Scanning kit directory: {args.kit_base_dir}", file=sys.stderr)
        load_from_kit_files(
            args.kit_base_dir,
            kit_artifacts,
            max_file_size=args.max_file_size,
            max_files_per_kit=args.max_files_per_kit,
            kit_timeout_seconds=args.kit_timeout_seconds,
            progress_every=args.progress_every,
        )
        print(f"      -> {len(kit_artifacts)} kits total", file=sys.stderr)

    # Build identifier keys per kit
    print("[Cluster] Building identifier keys...", file=sys.stderr)
    kit_identifiers: Dict[str, Set[str]] = {}
    for kit_name, arts in kit_artifacts.items():
        ids = build_identifier_keys(
            arts,
            include_weak_identifiers=args.include_weak_identifiers,
        )
        if ids:
            kit_identifiers[kit_name] = ids

    print(f"          -> extracted identifiers from {len(kit_identifiers)} kits", file=sys.stderr)
    if not args.include_weak_identifiers:
        print(
            "          -> weak_email/dump_filename are stored in artifacts but excluded from clustering keys "
            "(pass --include-weak-identifiers to include them)",
            file=sys.stderr,
        )

    # Union-Find clustering
    print("[Cluster] Running Union-Find clustering...", file=sys.stderr)
    uf, id_to_kits = cluster(kit_identifiers)

    # Save outputs
    print(f"[Output] Saving results: {args.out_dir}", file=sys.stderr)
    summary = save_outputs(args.out_dir, kit_identifiers, kit_artifacts, uf, id_to_kits)

    print("[Done]", file=sys.stderr)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
